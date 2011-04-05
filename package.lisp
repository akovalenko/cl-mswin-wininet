;;;; package.lisp

(defpackage #:wininet
  (:use #:cl #:sb-alien)
  (:import-from #:sb-win32
		#:system-string
		#:dword)
  (:export   #:*wininet-default-flags*
             #:advise-quicklisp
             #:get-quicklisp
             #:*quicklisp-use-wininet*))
