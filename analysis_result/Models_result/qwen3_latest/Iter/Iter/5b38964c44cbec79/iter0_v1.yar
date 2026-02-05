rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 53 FF 15 ?? ?? ?? ?? }  // Push ebx + Call (VM check)
        $pattern1 = { 50 FF 15 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? }  // Push eax + Call + Call (VM check)
        $pattern2 = { FF 75 08 E8 ?? ?? ?? ?? }  // Push ebp+08h + Call (VM check)

    condition:
        any of them
}