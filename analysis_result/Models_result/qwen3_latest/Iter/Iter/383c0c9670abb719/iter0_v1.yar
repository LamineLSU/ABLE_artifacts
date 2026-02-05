rule MaliciousBehavior
{
    meta:
        description = "Detects malicious behavior involving control flow hijacking and process injection"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
    
    strings:
        $a = { 85 C0 74 ?? 50 FF 15 ?? ?? ?? ?? }  // Test EAX, short jump, push EAX, call
        $b = { 0F 84 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? }  // Long jump, load effective address
        $c = { FF 15 ?? ?? ?? ?? 53 FF 15 ?? ?? ?? ?? }  // Call, push EBX, call
    
    condition:
        all of ($a, $b, $c)
}