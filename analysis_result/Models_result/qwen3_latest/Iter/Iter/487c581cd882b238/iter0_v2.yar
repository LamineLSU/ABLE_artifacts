rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 53 FF 15 ?? ?? ?? ?? }  // Call to sandbox check with preceding push ebx
        $pattern1 = { FF 75 08 FF 15 ?? ?? ?? ?? }  // Call to sandbox check with preceding push dword
        $pattern2 = { E8 0B 00 00 00 FF 15 ?? ?? ?? ?? }  // Call to sandbox check with preceding call

    condition:
        any of them
}