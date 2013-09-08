#
# $Id$
# $Revision$
#

module Msf

###
#
# This class hooks all session creation events and allows automated interaction
# This is only an example of what you can do with plugins
#
###

class Plugin::SessionTagger < Msf::Plugin

	include Msf::SessionEvent

	attr_accessor :reg_ids

	def on_session_open(session)
		print_status("Hooked session #{session.sid} / #{session.session_host}")

		options = {data: {host: "#{session.session_host}", session: "#{session.sid}"}, collapse_key: "updated_score"}
		response = gcm.send_notification(@reg_ids, options)

		#session.shell_write("MKDIR C:\\TaggedBy#{ENV['USER']}\n")

		# Read output with session.shell_read()
	end

	def on_session_close(session,reason='')
		print_status("Hooked session #{session.sid} is shutting down")
	end

	def initialize(framework, opts)
		super


		begin
			require 'gcm'
		rescue LoadError
			raise "WARNING: GCM gem not found, Please 'gem install gcm'"
		end

		api_key = opts['apikey']
		registration_id = opts['id']
		@reg_ids = [registration_id] # an array of one or more client registration IDs

		gcm = GCM.new(api_key)
		self.framework.events.add_session_subscriber(self)
	end

	def cleanup
		self.framework.events.remove_session_subscriber(self)
	end

	def name
		"gcm_notify"
	end

	def desc
		"Send a GCM message for each new session"
	end

end
end

