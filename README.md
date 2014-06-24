glassfish-jdbc-realm-extented
=============================

Description:
------------

**Glassfish realm supporting JDBC authentication.**
*(this realm includes, None, [Bcrypt](http://www.mindrot.org/projects/jBCrypt/) and [MessageDigest](http://docs.oracle.com/javase/7/docs/api/java/security/MessageDigest.html) encryption)*

###### Mandatory properties:
....* `jaas-context`: JAAS context name used to access to the LoginModule for authentication (ex: jdbcRealmExtended).
....* `datasource-jndi`: the datasource jndi name.
....* `db-user`: the datasource username (if the datasource username was define into the datasource jndi configuration then this parameter isn't mandatory).
....* `db-password`: the datasource password (if the datasource password was define into the datasource jndi configuration then this parameter isn't mandatory).
....* `user-table`: the table name containing username and password.
....* `user-name-column`: the column name corresponding to username in user-table and group-table.
....* `password-column`: the column name corresponding to password in user-table.
....* `group-table`: the table name containing username and group name.
....* `group-name-column`: the column name corresponding to group in group-table.
....* `group-table-user-name-column`: the column name corresponding to username in group-table (this property isn't mandatory if the group-table property is equals to the user-table property).

###### Optional properties:
....* `digest-algorithm`: the algorithm used to encrypt user password(values: *none*, *bcrypt*, *SHA-256*, *SHA-1* or *MD5*).
....* `password-salt`: the plaintext salt to append to a user plaintext password.
....* `bcrypt-log-rounds`: the {@link <a href="http://www.mindrot.org/projects/jBCrypt/">Bcrypt</a>} log rounds.
....* `encoding`: an encoding type (values:hex or base64).
....* `charset`: a {@link Charset} name.

**WARNING**: If the digest-algorithm is equals to 'none' value, user password won't be encrypted into the database.
.............Ifthe digest-algorithm property isn't defined, the digest-algorithm property will correspond to the default-digest-algorithm
.............property defined into the glassfish security config(By default: SHA-256).
.............If the default-digest-algorithm property isn't defined, the digest-algorithm property will correspond to SHA-256

