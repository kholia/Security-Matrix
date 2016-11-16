## Fedora Security Matrix

[Security Matrix for Fedora](https://fedoraproject.org/wiki/Security_Features_Matrix)

### Setup

* dnf install rubygem-wikicloth python2-mwclient -y

### Notes

* `matrix_generator_fedora.py` script generates the markup behind the [Fedora Security Matrix](https://fedoraproject.org/wiki/Security_Features_Matrix) page.

* Fedora Wiki is based on MediaWiki. Ubuntu Wiki uses MoinMoin.

* To install MediaWiki on Fedora, use the following steps,

  ```
  dnf install mediawiki php-pear-MDB2-Driver-mysqli mariadb-server -y
  ```

  ```
  vim /etc/httpd/conf.d/mediawiki.conf  # uncomment the "Alias" lines suitably
  ```

  ```
  systemctl start httpd.service
  ```

### Authors

* Siddharth Sharma (sidhax)

* Dhiru Kholia (kholia)

### References

* https://fedoraproject.org/wiki/Security_Features_Matrix

* https://fedoraproject.org/w/index.php?title=Security_Features_Matrix&action=edit

* https://wiki.ubuntu.com/Security/Features?action=raw

* https://wiki.ubuntu.com/Security/Features (review this periodically)

* http://bazaar.launchpad.net/~ubuntu-security/ubuntu-cve-tracker/master/files/head:/scripts/

* https://access.redhat.com/site/articles/65299

* http://www.awe.com/mark/blog/200801070918.html
