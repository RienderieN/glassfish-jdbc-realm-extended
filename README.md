# glassfish-jdbc-realm-extented
*Glassfish realm supporting JDBC autentication.*


This realm includes several encryption algorithms:
- `None`: user password isn't encrypted (a plaintext password)
- `Bcrypt`: user password encrypted with [jBCrypt](http://www.mindrot.org/projects/jBCrypt/)
- `SHA-256`, `SHA-1` or `MD5`: user password encrypted with [MessageDigest](http://docs.oracle.com/javase/7/docs/api/java/security/MessageDigest.html)


The JDCB Realm needs the following properties in its configuration:
- **Mandatory properties:**
>   - `jaas-context`: JAAS context name used to access LoginModule for authentication (for example *jdbcRealmExtended*)
>   - `datasource-jndi`: datasource jndi name.
>   - `db-user`: datasource user name (if the datasource user name was define into the datasource jndi configuration then this property isn't mandatory).
>   - `db-password`: datasource password (if the datasource password was define into the datasource jndi configuration then this property isn't mandatory).
>   - `user-table`: table name containing user name and password.
>   - `user-name-column`: column name corresponding to user name in user-table.
>   - `password-column`: column name corresponding to password in user-table.
>   - `group-table`: table name containing group name.
>   - `group-name-column`: column name corresponding to group in group-table.
>   - `group-table-user-name-column`: column name corresponding to user name in group-table (this property isn't mandatory if the `group-table` property is equals to the `user-table` property).

- **Optional properties:**
>   - `digest-algorithm`: algorithm used to encrypt user password (values: `None`, `Bcrypt`, `SHA-256`, `SHA-1` or `MD5`).
>   - `password-salt`: plaintext password salt.
>   - `bcrypt-log-rounds`: [jBCrypt](http://www.mindrot.org/projects/jBCrypt) log rounds.
>   - `encoding`: encoding type (values: `hex` or `base64`).
>   - `charset`: Charset name.

**WARNING:**

If the `digest-algorithm` property is equals to `None` value, user password isn't encrypted.<br/>
If the `digest-algorithm` property isn't defined, the `digest-algorithm` will correspond to the `default-digest-algorithm` property defined into the Glassfish security config (by default it's `SHA-256`).<br/>
If the `default-digest-algorithm`property isn't defined, the `digest-algorithm` property will correspond to `SHA-256`.
