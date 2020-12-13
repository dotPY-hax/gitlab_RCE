# Gitlab RCE - Remote Code Execution
RCE for old gitlab version &lt;= 11.4.7

This an exploit for old Gitlab versions. The vulnerability is from 2018 so this shouldnt work in the wild but it still seems to be popular in CTFs. 
Educational use only. Illegal things are illegal.

CVEs: CVE-2018-19571 (SSRF) + CVE-2018-19585 (CRLF)

credits: 

  https://www.youtube.com/watch?v=LrLJuyAdoAg - LiveOverflow  
  https://github.com/jas502n/gitlab-SSRF-redis-RCE - jas502n
  
usage:

  python gitlab_rce.py <http://gitlab:port> <local-ip>
  
  You might or might not have to tweak this a bit. For example the redis port (6379) might be different for your target.

THERE ARE ABSOLUTELY !!NO!! CHECKS OR ERROR HANDLING! 
