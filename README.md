# Overview
This was designed as a simple (but not drop-in) replacement for the finger
daemon packaged with OpenLDAP. It has close to feature parity, but I have made a
few minor changes to the algorithm.

## Quick start
The example config should work with only a few modifications:

1. Change the `name` field under servers to match your LDAP server
2. Change the `ldaphost` to match your LDAP server. If doing TLS this should match the certificate the server is using.
3. Change the `basedn` field under servers to match your LDAP tree
4. Set appropriate TLS settings, you likely don't need the `tlscacert` field at all
5. Change the `objectClasses` to match your LDAP tree. This will take some knowledge of your LDAP setup as these tend to change between vendors.
6. Add any rules you would like. In particular uupid likely needs to change to match your LDAP tree's username field.

You can build the project with `go build`, but you'll want to set capabilities on the binary if it'll be binding to port 79.

    setcap 'cap_net_bind_service=+ep' go-finger-ldap

Then simply run the program and pass it the config file.

    ./go-finger-ldap -f example.yaml

# Configuration
The example configuration file provides all of the values that can be parsed.
It is organized into a hierarchy of global settings, an array of servers with
server settings and an array of `lookups` which represent LDAP objects with
common attributes, and an array of rules for composing queries in the `lookups`.

## Global

There are only two fields here, `bindaddress` which is a host and port
combination the server should bind to and `servers` which is an array of server
objects.

## Server
The server manages the settings for the LDAP connection to that server. It has
a `name`, `ldaphost` (if you're using TLS it will use this name as the
ServerName), `ldapport`, `basedn`, TLS settings, and array of
`lookups`. If `tls` is set to true, then the connection will fail if it can't
successfully setup TLS. The `tlscacert` is used where the LDAP server is using
a self-signed or custom CA. This is just a string blob of the CA certificate
used. It will append this to the system's CA certs.

## Lookup
A `lookup` represents a group of objectClasses with shared attributes. For
example you may have multiple Person type objects. It has the fields `name`,
`objectClasses` which is an array of objectClass the LDAP query should
return, `attributes` which is an array of attribute objects, and `rules`
which is an array of rule objects.

### Attribute
An attribute object has four fields, `name`, `prettyname`, and `bulk`. The
`name` field is name of the attribute in LDAP where `prettyname` is what will
be displayed to the client. The `bulk` field lets the daemon know what fields
it should return if multiple results are retrieved and defaults to false. You
definitely want some attributes with `bulk` set to true. The order of the
attributes is the order in which they will be displayed.

### Rule
The rules where `regex` matches the query are processed in order returning all the results from the first match. The `name` field is used to tell the client how the match was made. The `filter` field describes the LDAP filter that should be used. This should be well-formed in parentheses. Any instance of `%v` will be replaced by the query unless `split` is true. In that case, the query is split by white space and the LDAP filter is formed by joining each term with an or clause.

    name: partial name
    regex: .+
    filter: (cn=*%v*)
    split: true

The query "Dale Cooper" will be turned into the filter `(|(cn=*Dale*)(cn=*Cooper*))`.
