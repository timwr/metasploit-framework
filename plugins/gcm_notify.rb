#
# $Id$
# $Revision$
#


module Msf

###
#
# This class hooks all session creation and sends a gcm notification with session id
#
###

class Plugin::GCMNotify < Msf::Plugin

	include Msf::SessionEvent

	attr_accessor :gcm
	attr_accessor :reg_id

	def on_session_open(session)
		options = {data: {host: "#{session.session_host}", session: "#{session.sid}"}}
		response = @gcm.send_notification([reg_id], options)
	end

	def initialize(framework, opts)
		super

		begin
			require "gcm"
		rescue LoadError
			raise "WARNING: GCM gem not found, Please 'gem install gcm'"
		end

		api_key = opts[:api_key] || opts['api_key']
		@reg_id = opts[:reg_id] || opts['reg_id']

		self.gcm = GCM.new(api_key)
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

