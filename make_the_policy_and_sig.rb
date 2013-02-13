require 'base64'
require 'openssl'
require 'json'

@aws_bucket = "XXXXXXXXXXXXXXXXXXXXXXX"
@aws_access_key = "XXXXXXXXXXXXXXXXXXXXXXX"
@aws_secret_key = "XXXXXXXXXXXXXXXXXXXXXXX"

def signature(options = {})
  Base64.encode64(
    OpenSSL::HMAC.digest(
      OpenSSL::Digest::Digest.new('sha1'),
      @aws_secret_key,
      policy({ secret_access_key: @aws_secret_key })
    )
  ).gsub(/\n/, '')
end
 
def policy(options = {})
  # 5242880 is 5 megabytes
  Base64.encode64(
    { 
      expiration: '2040-01-01T01:01:01.000Z', #far future
      conditions: [
        { bucket: @aws_bucket },
        { acl: 'public-read' },
        { success_action_status: '201'},	
        { success_action_redirect: "XXXXXXXXXXXXXXXXX" },     
        ["starts-with", "$key", ""],
        ["starts-with", "$Content-Type", ""],
        ["content-length-range", 0, 5242880]
      ]
    }.to_json
  ).gsub(/\n|\r/, '')
end

puts signature

puts "--"

puts policy