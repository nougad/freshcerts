#!/usr/bin/env ruby
require 'openssl'
require 'active_support/time'
require './common'

module Freshcerts::Monitoring
  def self.check_site(domain, portdata, wanted_hash)
    if portdata[:protocol]
      check_site_starttls(domain, portdata[:port], portdata[:protocol], wanted_hash, &Proc.new)
    else
      check_site_ssl(domain, portdata[:port], wanted_hash, &Proc.new)
    end
  end

  def self.check_site_starttls(domain, port, protocol, wanted_hash)
    cmd = "openssl s_client -servername #{domain} -connect #{domain}:#{port} -starttls #{protocol} 2>/dev/null </dev/null | openssl x509 -fingerprint -sha256 -noout -in /dev/stdin"
    result = `#{cmd}`
    if result =~ /^SHA256 Fingerprint=([0-9A-F:]+)/
      found_hash = $1.downcase
      yield (wanted_hash == found_hash ? :ok : :wrong_cert), found_hash
    else
      raise "unexpected output for command `#{cmd}`: `#{result}`"
    end
  end

  def self.check_site_ssl(domain, port, wanted_hash)
    OpenSSL::SSL::SSLSocket.new(TCPSocket.new domain, port).tap do |sock|
      sock.hostname = domain
      sock.sync_close = true
      sock.connect
      found_hash = Freshcerts.hash_cert sock.peer_cert
      yield (wanted_hash == found_hash ? :ok : :wrong_cert), found_hash
      sock.close
    end
  end

  def self.check_sites
    Freshcerts.sites.all.each do |domain, site|
      site.ports.map! do |port|
        if port.is_a?(Hash)
          port
        else # convert old data (no protocol)
          {:protocol => nil, :port => port}
        end
      end

      site.ports.each do |portdata|
        begin
          msg = "#{domain}:#{portdata[:protocol]}/starttls:#{portdata[:protocol] || 'no'}"

          puts "Checking #{msg}"
          wanted_hash = site.cert_sha256
          check_site(domain, portdata, wanted_hash) do |status, found_hash|
            if status == :wrong_cert
              Freshcerts.notify_admin "monitoring found cert error for #{msg}",
                "Found a certificate with SHA-256 figerprint\n\n#{found_hash}\n\n, should be\n\n#{wanted_hash}."
              puts "#{msg} wrong cert: #{found_hash}, should be #{wanted_hash}"
            else
              puts "#{msg} ok"
            end
            site.status = status
          end
        rescue => e
          Freshcerts.notify_admin "monitoring could not connect to #{msg}",
            "Could not connect to #{msg}.\n\nException: #{e.class}: #{e.message}\nBacktrace:\n#{e.backtrace.join "\n"}"
          puts "#{msg} exception: #{e}"
          site.status = :conn_error
        end
        site.last_checked = Time.now
        Freshcerts.sites[domain] = site
        sleep 2.seconds
      end
    end
  end
end

if File.identical?(__FILE__, $0)
  Freshcerts::Monitoring.check_sites
end
