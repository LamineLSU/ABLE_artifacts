rule Malware_Detection
{
    meta:
        description = "Detects malware based on specific behavioral patterns"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
        confidence = 75

    strings:
        $a = { 85 C0 74 12 6A 5B 5A 8B CE }  // Test, JE, Push, Pop, Mov
        $b = { 85 C0 0F 84 ?? ?? ?? ?? }     // Test followed by JE (variable offset)
        $c = { FF 15 2C A1 1A 00 }          // Call to ExitProcess (API call)

    condition:
        all of them
}