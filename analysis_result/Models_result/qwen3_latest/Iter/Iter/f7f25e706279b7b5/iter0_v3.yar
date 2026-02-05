rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 52 E8 ?? ?? ?? ?? }  // Push edx + Call edx (heap allocation check)
        $pattern1 = { 50 E8 ?? ?? ?? ?? }  // Push eax + Call (control flow check)
        $pattern2 = { 8D B0 A0 0C 00 00 E8 ?? ?? ?? ?? }  // LEA esi + Call (address manipulation check)

    condition:
        all of them
}