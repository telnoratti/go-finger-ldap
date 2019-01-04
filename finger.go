// Copyright 2019 Calvin Winkowski. All rights reserved. Use of this
// source code is governed the MIT license that can be found in the
// LICENSE file.

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	flags "github.com/jessevdk/go-flags"
	finger "github.com/mitchellh/go-finger"
	"gopkg.in/ldap.v3"
	"gopkg.in/yaml.v2"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"text/tabwriter"
)

var config Conf

type Conf struct {
	BindAddress string       `yaml:"bindaddress"`
	Servers     []LDAPServer `yaml:"servers"`
}

type LDAPServer struct {
	Name        string       `yaml:"name"`
	LDAPHost    string       `yaml:"ldaphost"`
	LDAPPort    string       `yaml:"ldapport"`
	StartTLS    bool         `yaml:"starttls"`
	TLS         bool         `yaml:"tls"`
	TLSCACert   string       `yaml:"tlscacert"`
	BaseDN      string       `yaml:"basedn"`
	LDAPLookups []LDAPLookup `yaml:"lookups"`
}

type LDAPLookup struct {
	Name           string          `yaml:"name"`
	ObjectClasses  []string        `yaml:"objectClasses"`
	Rules          []LDAPRule      `yaml:"rules"`
	Attributes     []LDAPAttribute `yaml:"attributes"`
	attributeNames []string
	server         *LDAPServer
}

type LDAPAttribute struct {
	Name       string `yaml:"name"`
	PrettyName string `yaml:"prettyname"`
	Bulk       bool   `yaml:"bulk,omitempty"`
}

type LDAPRule struct {
	Name          string `yaml:"name"`
	Filter        string `yaml:"filter"`
	Split         bool   `yaml:"split"`
	Regex         string `yaml:"regex"`
	compiledRegex *regexp.Regexp
	lookup        *LDAPLookup
}

func queryLDAPLookup(search string, basedn string, ldapConn *ldap.Conn, lookup *LDAPLookup) (*ldap.SearchResult, *LDAPRule, error) {
	for _, rule := range lookup.Rules {
		// First verify the search string matches the rule regex
		//log.Println(search)
		if !rule.compiledRegex.MatchString(search) {
			continue
		}

		// Next we construct the filter
		var filter strings.Builder
		filter.WriteString("(&(|") // Match one of objectclass and ...
		for _, class := range lookup.ObjectClasses {
			fmt.Fprintf(&filter, "(objectclass=%s)", class)
		}
		filter.WriteString(")")
		//log.Println(filter.String())

		// If split,
		if rule.Split {
			// we need to split on whitespace and apply the filter
			// multiple times in an "or"
			filter.WriteString("(|")
			for _, term := range strings.Split(search, " ") {
				filter.WriteString("(")
				// search is input from the user, let's treat it
				// carefully (don't use Fprintf)
				filter.WriteString(strings.Replace(rule.Filter, "%v", term, -1))
				filter.WriteString(")")
			}
			filter.WriteString(")")
		} else {
			filter.WriteString("(")
			// search is input from the user, let's treat it
			// carefully (don't use Fprintf)
			filter.WriteString(strings.Replace(rule.Filter, "%v", search, -1))
			filter.WriteString(")")
		}
		// This closes the original "and"
		filter.WriteString(")")
		//log.Printf("Trying to use search '%s'\n", filter.String())

		// Now we construct the SearchRequest and get results
		searchRequest := ldap.NewSearchRequest(basedn, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, filter.String(), lookup.attributeNames, nil)
		results, err := ldapConn.Search(searchRequest)
		if err != nil {
			// If we have an error, give the other rules a shot
			// TODO check type of error and only ignore LDAP errors
			log.Println(err)
			continue
		}
		// If results, return them
		if len(results.Entries) > 0 {
			return results, &rule, nil
		}
	}
	return nil, nil, nil
}

func queryLDAPServer(search string, server *LDAPServer) (*ldap.SearchResult, *LDAPRule, error) {
	var ldapConn *ldap.Conn
	var err error
	if server.TLS {
		tlsConfig := &tls.Config{ServerName: server.LDAPHost}

		// Change the root CAs if necessary
		if server.TLSCACert != "" {
			rootCAs, _ := x509.SystemCertPool()
			if rootCAs == nil {
				rootCAs = x509.NewCertPool()
			}
			if ok := rootCAs.AppendCertsFromPEM([]byte(server.TLSCACert)); !ok {
				return nil, nil, errors.New("Could not add TLS cert from config")
			}
			tlsConfig.RootCAs = rootCAs
		}

		if server.StartTLS {
			ldapConn, err = ldap.Dial("tcp", fmt.Sprintf("%s:%s", server.LDAPHost, server.LDAPPort))
			if err != nil {
				return nil, nil, err
			}
			defer ldapConn.Close()
			err = ldapConn.StartTLS(tlsConfig)
			if err != nil {
				return nil, nil, err
			}
		} else {
			ldapConn, err = ldap.DialTLS("tcp", fmt.Sprintf("%s:%s", server.LDAPHost, server.LDAPPort), tlsConfig)
			if err != nil {
				return nil, nil, err
			}
			defer ldapConn.Close()
		}
	}

	hadSuccess := false
	for _, lookup := range server.LDAPLookups {
		results, rule, err := queryLDAPLookup(search, server.BaseDN, ldapConn, &lookup)
		if err != nil {
			log.Println(err)
		} else {
			hadSuccess = true
		}
		// We do need to check that results were returned
		if results != nil && len(results.Entries) > 0 {
			return results, rule, nil
		}
	}
	if hadSuccess == false {
		// indicate we had catastrophic failure which is almost
		// certainly a config problem or service outage
		return nil, nil, errors.New("No LDAP queries were successful")
	}
	return nil, nil, nil
}

func handleFinger(ctx context.Context, w io.Writer, q *finger.Query) {
	// Our results will get written into response. Defining it here will
	// let us accumulate results if we so desire.
	var response strings.Builder
	for i := range config.Servers {
		server := &config.Servers[i]
		results, rule, err := queryLDAPServer(q.Username, server)
		if err != nil {
			// In this instance we probably want to communicate to the
			// user the server appears down
			log.Println(err)
			w.Write([]byte(err.Error()))
			continue
		}

		if results != nil && len(results.Entries) != 0 {
			// we had successful results
			if len(results.Entries) > 1 {
				fmt.Fprintln(&response, "Many entries for", q.Username, "matching on", rule.Name)
				twriter := tabwriter.NewWriter(&response, 0, 0, 3, ' ', tabwriter.AlignRight)
				// We're going to print a list of users in the form username, uupid, cn, title
				bulkAttributes := make([]LDAPAttribute, 0)
				for _, attribute := range rule.lookup.Attributes {
					if attribute.Bulk == true {
						bulkAttributes = append(bulkAttributes, attribute)
					}
				}
				// Print a header
				for _, attribute := range bulkAttributes {
					fmt.Fprintf(twriter, "%s\t", attribute.PrettyName)
				}
				fmt.Fprintf(twriter, "\r\n")
				for _, entry := range results.Entries {
					for _, attribute := range bulkAttributes {
						fmt.Fprintf(twriter, "%s\t", entry.GetAttributeValue(attribute.Name))
					}
					fmt.Fprintf(twriter, "\r\n")
					//	fmt.Fprintf(twriter, "%s\t%s\t%s\t%s\r\n", entry.GetAttributeValue("uupid"), entry.GetAttributeValue("uid"), entry.GetAttributeValue("cn"), entry.GetAttributeValue("title"))
				}
				twriter.Flush()
				// We had success, let's quit
				w.Write([]byte(response.String()))
				return
			} else { // We only have one result, so let's be detailed
				fmt.Fprintln(&response, "One entry for", q.Username, "matching on", rule.Name)
				entry := results.Entries[0]
				for _, field := range rule.lookup.Attributes {
					if entry.GetAttributeValue(field.Name) != "" {
						fmt.Fprintf(&response, " %s:\r\n               %s\r\n", field.PrettyName, strings.Replace(entry.GetAttributeValue(field.Name), "$", "\r\n               ", -1))
					}
				}
				// We had success, let's quit
				w.Write([]byte(response.String()))
				return
			}
		} // Have results if
	} // server for loop
	// If we're here, then we've had no results
	response.Write([]byte(fmt.Sprintf("No results found for %s\r\n", q.Username)))
	w.Write([]byte(response.String()))
}

func main() {
	var opts struct {
		ConfigFile string `short:"f" long:"file" description:"YAML config file to read" required:"true"`
	}
	_, err := flags.ParseArgs(&opts, os.Args)
	if err != nil {
		os.Exit(1)
	}

	// Get configData from where we're told
	var configData []byte
	if opts.ConfigFile == "-" {
		configData, err = ioutil.ReadAll(os.Stdin)
	} else {
		configData, err = ioutil.ReadFile(opts.ConfigFile)
	}
	if err != nil {
		log.Fatal(err)
	}

	// configData is now full of yaml (hopefully)
	err = yaml.Unmarshal(configData, &config)
	if err != nil {
		log.Fatal(err)
	}

	// Precompile regex and generate key slices
	for i := range config.Servers {
		server := &config.Servers[i]
		for i := range server.LDAPLookups {
			lookup := &server.LDAPLookups[i]
			// Generate key slice for later
			lookup.attributeNames = make([]string, len(lookup.Attributes))
			i := 0
			for _, attribute := range lookup.Attributes {
				lookup.attributeNames[i] = attribute.Name
				i++
			}
			// Compile regexes and set backreferences
			for i := range lookup.Rules {
				rule := &lookup.Rules[i]
				rule.compiledRegex = regexp.MustCompile(rule.Regex)
				rule.lookup = lookup
			}
			// Set backreference
			lookup.server = server
		}
	}

	listener, err := net.Listen("tcp", config.BindAddress)
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()

	// Start the server
	server := &finger.Server{Handler: finger.HandlerFunc(handleFinger)}
	go server.Serve(listener)

	// Wait for a reason to quit
	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	s := <-sig
	fmt.Printf("Signal (%s) received, stopping\n", s)
}

// vim: tabstop=4 softtabstop=4 shiftwidth=4 noexpandtab tw=72
