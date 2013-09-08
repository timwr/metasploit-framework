
begin
    require 'gcm'
rescue LoadError
    raise "WARNING: GCM gem not found, Please 'gem install gcm'"
end

api_key = 'AIzaSyCOD6wdzmSOWp5iOuQGGv-z5S10hM6uAMQ'

registration_id = 'APA91bESo1xt5PSTvQScsp1bDvOu_W5Zi4yyYc6cJl08b8ccuHaG3Y4rRpRWVXm3fFvTiE-jZAIMkUjviqZsqznuuMor-zjNBDmolNMo01A0SD_ONnE2E1QVoqzrjvdukkPFa9Xj8tQhiknnW59F9zSFGZQ0AdD7HA'

gcm = GCM.new(api_key)
registration_ids = [registration_id] # an array of one or more client registration IDs
options = {data: {session: "123"}, collapse_key: "updated_score"}
response = gcm.send_notification(registration_ids, options)


