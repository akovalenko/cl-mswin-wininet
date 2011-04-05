;;;; wininet.lisp -- support for MS Windows network client library.
;;; by Anton Kovalenko, A.D. 2011; placed into public domain.
;;;
;;; There are plenty of good HTTP libraries available; however,
;;; wininet.dll may have a significant [though unfair] advantage in a
;;; 'hostile` environment: consider proxy autoconfiguration [with DLLs
;;; and ActiveX], and authentication methods integrated with Active
;;; Directory.
;;;
;;; Support for wininet.dll means that we are able to access HTTP
;;; servers if the software coming with MS Windows is doing the same.
;;; 
;;; There is another client library integrated in Windows:
;;; winhttp.dll. It is intended for use in services [daemons] and
;;; other non-interactive software. Wininet and winhttp APIs have many
;;; similarities, and supporting the latter one here wouldn't be too
;;; hard; however, winhttp doesn't have the main property for which
;;; wininet may be desirable: it can't handle proxy autoconfiguration
;;; and other atrocities of this kind, and even if IE and Outlook are
;;; accessing the Internet, winhttp may fail. And without that unfair
;;; advantage of wininet.dll, winhttp itself is not too interesting.
 
(defparameter wininet::*user-package* *package*)
(in-package #:wininet)

(load-shared-object #P"wininet.dll")

;;; Create an internet session: the topmost object in wininet handle
;;; hierarchy. [Correcting myself: the topmost object is a handle with
;;; NULL value].
(define-alien-routine ("InternetOpenW" wininet-open) signed
  (user-agent system-string)
  (access-type dword)
  (proxy system-string)
  (proxy-bypass system-string)
  (flags dword))

;;; Close any handle of type HINTERNET, be it a session, server or
;;; request handle, or some other kind of handle that we don't mention
;;; here.
(define-alien-routine ("InternetCloseHandle" wininet-close) boolean
  (handle signed))

;;; Connect to server; this call is used for authenticated access,
;;; it is not required for anonymous downloads.
(define-alien-routine ("InternetConnectW" wininet-connect) signed
  (wininet-handle signed)
  (server system-string)
  (user system-string)
  (password system-string)
  (service dword)
  (flags dword)
  (context unsigned))

;;; Create and send a request, returning its handle. Wininet contains
;;; some more fine-grained routines for dealing with requests in
;;; smaller steps, but we don't provide binding for them here.
(define-alien-routine ("InternetOpenUrlW" wininet-open-url) signed
  (wininet-handle signed)
  (url system-string)
  (headers system-string)
  (headers-length dword)
  (flags dword)
  (context unsigned))

;;; Data input routine modelled after ReadFile. Works with the _body_
;;; of downloaded content: other routines are needed if you want to
;;; examine headers, response code etc.
(define-alien-routine ("InternetReadFile" wininet-read) boolean
  (wininet-handle signed)
  (buffer (* t))
  (bytes-to-read dword)
  (bytes-read dword :out))

;;; Retrieve the size of _immediately available_ _buffered data_.
(define-alien-routine ("InternetQueryDataAvailable" wininet-data-available) boolean
  (wininet-handle signed)
  (length dword :out)
  (flags dword)
  (context unsigned))

;;; Retrieve an HTTP-specific piece of information about the request,
;;; in ioctl-like manner.
(define-alien-routine ("HttpQueryInfoW" http-query-info) boolean
  (request-handle signed)
  (info-level dword)
  (buffer (* t))
  (buffer-length dword :in-out)
  (index dword :in-out))

;;; Retrieve a piece of general-purpose information about the request
;;; or a higher-level entity [server, session], also in ioctl-like
;;; manner. Many options are writable as well: see the next
;;; definition.
(define-alien-routine ("InternetQueryOptionW" internet-query-option) boolean
  (request-handle signed)
  (option dword)
  (buffer (* t))
  (buffer-length dword :in-out))

;;; Modify a piece of general-purpose information or settings for the
;;; request or a higher-level entity.
(define-alien-routine ("InternetSetOptionW" internet-set-option) boolean
  (request-handle signed)
  (option dword)
  (buffer (* t))
  (buffer-length dword))

(defmacro query-info-fixed-size (request-handle info-level info-alien-type &key (index 0))
  `(with-alien ((result-buffer ,info-alien-type))
     (unless (http-query-info ,request-handle ,info-level
			      (addr result-buffer) (alien-size ,info-alien-type :bytes) ,index)
       (sb-win32::win32-error 'http-query-info))
     result-buffer))

#-(and)
(defun request-content-length (request-handle)
  ;; No idea why it doesn't work. Tested only on Wine for now: real
  ;; Windows may be better.
  (query-info-fixed-size request-handle (logior #x20000000 5 ) dword))

(defun request-raw-headers (request-handle)
  "HTTP headers, as a string consisting of CRLF-delimited lines."
  (with-alien ((headers (array char 16384)))
    (http-query-info request-handle 22 (alien-sap headers) 16384 0)
    (with-alien ((pointer (* char) (cast headers (* char))))
      (cast pointer (c-string :external-format :ucs-2)))))

(defun request-content-length (request-handle)
  "Content-Length field returned by server, or NIL if no such header.
The implementation is tricky: a commented-out version above tries to
retrieve the length as number, but that version was observed to fail.
This routine requests length in the string form, and parses it."
  (with-alien ((headers (array char 16384)))
    (and (http-query-info request-handle 5 (alien-sap headers) 16384 0)
         (with-alien ((pointer (* char) (alien-sap headers)))
           (parse-integer
            (or (cast pointer (c-string :external-format :ucs-2)) ""))))))

(defun wininet-http-version ()
  "HTTP protocol version that wininet is instructed to use currently.
I've read on MSDN that this option is queried and set with NULL handle
value only."
  (with-alien ((version (array dword 2)))
    (internet-query-option 0 59 (alien-sap version)
                           (alien-size (array dword 2) :bytes))
    (format nil "~A.~A" (deref version 0) (deref version 1))))

(defparameter *wininet-flag-keywords*
  '(:reload :raw-data :reuse-existing-connection :asynchronous :passive
    :no-cache :make-persistent :from-cache :secure :keep-alive
    :no-auto-redirect :read-prefetch :no-cookies :no-auth :restricted-zone
    :from-cache-on-error :ignore-redirect-to-http :ignore-redirect-to-https
    :ignore-cert-date-invalid :ignore-cert-cn-invalid :resynchronize
    :hyperlink :no-ui :pragma-nocache :cache-async :forms-submit :fwd-back
    :need-file nil nil :binary-data :text-data)
  "Normally unchanged; list of human-readable names for HINTERNET
creation flag bits, corresponding to bits 31-0 [in that order].

Most routines that return HINTERNET accept a DWORD of flags, affecting
the behavior of the new handle. With respect to flags that I see
defined in the MinGW header now, almost any bit of 32-bit value is
used as a flag [two NILs above are positioned over the single 'hole'
in this sequence].")

(defparameter *wininet-flag-masks*
  (let ((hash-table (make-hash-table :test 'eq)))
    (loop for option in *wininet-flag-keywords*
       and flag = (ash 1 31) then (ash flag -1)
       when option do (setf (gethash option hash-table) flag)
       finally (return hash-table)))
  "Keyword to flag mask mapping represented as a hash table [Hmm. 30
elements -- alist or plist may be even faster, TODO test it].")

(defmacro with-hinternet ((handle open-form) &body body)
  "Execute BODY with `handle' bound to value of OPEN-FORM.
Handle is closed on any exit from the BODY."
  `(let ((,handle ,open-form))
     (case ,handle
       (0 (sb-win32::win32-error 'with-hinternet))
       (otherwise
	(unwind-protect ((lambda () ,@body))
	  (wininet-close ,handle))))))

(defvar *default-user-agent*
  (format nil "CL-WinInet on ~A ~A"
          (lisp-implementation-type)
          (lisp-implementation-version))
  "User-Agent header")

(defvar *session-hinternet* nil)
(defvar *server-hinternet* nil)
(defvar *url-hinternet* nil)

(defun repeatedly (&rest args)
  "Return a fresh circular list with args 'repeated' ad infinitum"
  (let ((once (copy-list args)))
    (nconc once once)))

(defun listify (thing) ;; or is it usually called ENSURE-LIST?
  (if (listp thing) thing (list thing)))

(defun flag-mask-from-keywords (list-or-flag)
  "Convert list of keywords to flag mask"
  (reduce #'logior (mapcar (lambda (position) (ash 1 (- 31 position)))
                           (mapcar #'position
                                   (listify list-or-flag)
                                   (repeatedly *wininet-flag-keywords*)))))

(defparameter *wininet-flag-joined-word*
  (flag-mask-from-keywords (remove nil *wininet-flag-keywords*))
  "Word with 1 in each bit standing for valid HINTERNET creation flag")

(defparameter *wininet-default-flags*
  '(:read-prefetch :keep-alive))

(defmacro with-standard-hinternet ((special-variable open-form) &body body)
  "Run BODY during the lifetime of HINTERNET handle opened by OPEN-FORM.
Fresh handle is requested only if SPECIAL-VARIABLE is false. If
dynamically nested functions use this form with the same parameters,
only the outermost one creates a handle.

Don't forget the downside of it: if some callers modify long-living
handles by adjusting parameters that affect Wininet behavior, they
assume full responsibility for unexpected settings (e.g. violating the
expectations of other callers)."
  `(with-hinternet (,special-variable (or ,special-variable ,open-form))
     ,@body))

(defparameter *quicklisp-http-names*
  '(:ql-http :qlqs-http)
  "List of package designators for possible packages containing
QUICKLISP's http client.")

(defparameter *quicklisp-use-wininet* t
  "If true, advised variants of quicklisp's FETCH function will use
this library.")

(defparameter *quicklisp-http-symbol-names*
  '(#:*maximum-redirects*
    #:*default-url-defaults*
    #:merge-urls
    #:urlstring
    #:process-header
    #:call-with-progress-bar
    #:cbuf-progress))

(defun map-form-symbols (function form)
  "Apply FUNCTION to each symbol within FORM, preserving its structure.
Return a fresh form. As of non-symbol objects, only sequences are
traversed."
  (labels ((frob (form)
             (typecase form
               (symbol (funcall function form))
               (sequence (map (type-of form) #'frob form))
               (t form))))
    (frob form)))

(defun http-to-stream (urlstring &key
                       (stream *standard-output*)
                       (open-url-flags *wininet-default-flags*)
                       (buffer-length 8192))
  "Download HTTP data and write it to STREAM."
  (let ((binary-output-p (typep 0 (stream-element-type stream))))
    (with-standard-hinternet (*session-hinternet* (wininet-open *default-user-agent* 0 nil nil 0))
      (with-hinternet (f (wininet-open-url *session-hinternet* urlstring nil 0
                                           (flag-mask-from-keywords open-url-flags) 0))
        (let ((buffer (make-array buffer-length
                                  :element-type '(unsigned-byte 8))))
          (sb-sys:with-pinned-objects (buffer)
            (let ((pointer (sb-sys:vector-sap buffer)))
              (loop
                 (multiple-value-bind (read some-bytes)
                     (wininet-read f pointer 8192)
                   (unless read (sb-win32::win32-error 'wininet-read))
                   (when (zerop some-bytes) (return))
                   (if binary-output-p
                       (write-sequence buffer stream :end some-bytes)
                       (write-sequence (sb-alien::octets-to-string buffer :end some-bytes) stream)))))))))))

(defun ql-http/fetch-redefinition-lambda (package)
  "Return a fresh lambda form reimplementing quicklisp's FETCH
function with WININET routines.  PACKAGE is a package designator,
normally either QLQS-HTTP or QL-HTTP. Resulting lambda form uses some
quicklisp's functions and data, with the same names and semantics for
full QL-HTTP and for lightweight/quickstart QLQS-HTTP.  Returned form
should be used to redefine quicklisp's FETCH in the same PACKAGE that
was given as an argument."
  (flet ((borrow (symbol)
           (if (member symbol *quicklisp-http-symbol-names* :key 'symbol-name :test 'string=)
               (find-symbol (string symbol) package)
               symbol)))
    (map-form-symbols
     #'borrow
     `(lambda (url file &key (follow-redirects t) quietly
               (if-exists :rename-and-delete)
               (maximum-redirects #:*maximum-redirects*)
               (open-url-flags *wininet-default-flags*))
        "Request URL and write the body of the response to FILE."
        (setf file (merge-pathnames file)
              url (#:merge-urls url #:*default-url-defaults*))
        (unless (and follow-redirects (plusp maximum-redirects))
          (pushnew :no-auto-redirect open-url-flags))
        (let ((stream (if quietly (make-broadcast-stream) *trace-output*)))
          (with-open-file (download file
                                    :direction :output :element-type :default
                                    :if-does-not-exist :create
                                    :if-exists if-exists)
            (with-standard-hinternet
                (*session-hinternet* (wininet-open *default-user-agent* 0 nil nil 0))
              (with-hinternet (f (wininet-open-url *session-hinternet* (#:urlstring URL) nil 0
                                                   (flag-mask-from-keywords open-url-flags) 0))
                (let ((size (request-content-length f))
                      (headers (#:process-header
                                (sb-alien::string-to-octets (request-raw-headers f)))))
                  (format stream "~&; Fetching ~A~%" url)
                  (if (and (numberp size)
                           (plusp size))
                      (format stream "; ~$KB~%" (/ size 1024))
                      (format stream "; Unknown size~%"))
                  (flet ((call-without-progress-bar (size function)
                           (declare (ignore size))
                           (funcall function))
                         (get-data (&optional (block-size 8192))
                           (let ((buffer (make-array block-size :element-type '(unsigned-byte 8))))
                             (sb-sys:with-pinned-objects (buffer)
                               (let ((pointer (sb-sys:vector-sap buffer)))
                                 (loop
                                    (multiple-value-bind (read some-bytes)
                                        (wininet-read f pointer block-size)
                                      (unless read (sb-win32::win32-error 'wininet-read))
                                      (when (zerop some-bytes)
                                        (return))
                                      (write-sequence buffer download :end some-bytes)
                                      (signal '#:cbuf-progress :size some-bytes))))
                               (values headers (and file (probe-file file)))))))
                    (funcall (if quietly
                                 #'call-without-progress-bar
                                 #'#:call-with-progress-bar) size #'get-data)
                    (values headers (and file (probe-file file)))))))))))))

(defun advise-quicklisp (&optional (package (some 'find-package *quicklisp-http-names*)))
  "Replace quicklisp's FETCH routine with a fresh compiled function
that uses WININET.DLL if *QUICKLISP-USE-WININET* is true."
  (unless package
    (error "quicklisp (or quicklisp-quickstart) HTTP package not found" ))
  (let ((original (intern (string '#:fetch/no-wininet) package))
        (redefined (intern (string '#:fetch/wininet) package))
        (current (intern (string '#:fetch) package))
        (lambda* (ql-http/fetch-redefinition-lambda package)))
    (unless (fboundp original)
      (setf (fdefinition original) (fdefinition current)))
    (let* ((fetch-lambda-list (second lambda*))
           (after-&key (member '&key fetch-lambda-list :test 'eq))
           (mandatory (ldiff fetch-lambda-list after-&key)))
      (compile current `(lambda (,@mandatory &rest args ,@after-&key &allow-other-keys)
                          ,(format nil "~A~&~%~@?"
                                   (documentation original 'function)
                                   "This function was advised by ~
                                   WININET package.  ~&It uses native ~
                                   Windows library to access HTTP servers ~
                                   ~&if WININET:*QUICKLISP-USE-WININET* is true.")
                          (declare (ignorable ,@(remove-if-not 'symbolp (rest after-&key))
                                              ,@(mapcar 'car (remove-if-not 'consp (rest after-&key)))
                                              ,@(remove nil (mapcar 'third (remove-if-not 'consp (rest after-&key))))))
                          (apply (if *quicklisp-use-wininet*
                                     ',(compile redefined lambda*)
                                     ',original)
                                 ,@mandatory args))))))

(progn 
  #1=
  (defun get-quicklisp (&key
                        (url "http://beta.quicklisp.org/quicklisp.lisp")
                        (pathname #.(make-pathname :directory '(:relative "quicklisp")))
                        (if-exists :error))
    "Download quicklisp bootstrap file with WININET.DLL and load it."
    (let ((quicklisp-bootstrap
           (make-pathname :defaults pathname :name "quicklisp" :type "lisp")))
      (ensure-directories-exist quicklisp-bootstrap)
      (format *debug-io* "~&Downloading ~A => ~A, please wait...~&" url quicklisp-bootstrap)
      (with-open-file (data quicklisp-bootstrap
                            :direction :output
                            :element-type :default
                            :if-exists if-exists)
        (http-to-stream url :stream data))
      (let ((sb-ext:*muffled-warnings* `(or ,sb-ext:*muffled-warnings*
                                         sb-kernel:redefinition-warning)))
        (load quicklisp-bootstrap))
      (advise-quicklisp "QLQS-HTTP")
      (format *debug-io* "~&QuickLisp installed, WININET redirection ~:[disabled~;enabled~].~&"
              *quicklisp-use-wininet*)
      quicklisp-bootstrap))

  (let ((*package* *user-package*))
    (format *debug-io* "~&~%Type ~S to download quicklisp bootstrapping file with WinInet.~
                      ~&DEFUN form start, just in case you need to know its arguments:~&"
            '(get-quicklisp)))
  (let ((*print-case* :downcase))
    (pprint `(,@'#.(subseq '#1# 0 3) [...]) *debug-io*)
    (terpri *debug-io*)))
