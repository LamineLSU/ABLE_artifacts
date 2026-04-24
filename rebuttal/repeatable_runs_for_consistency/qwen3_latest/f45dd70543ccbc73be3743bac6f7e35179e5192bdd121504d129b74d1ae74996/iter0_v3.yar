rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 53 FF 15 ?? ?? ?? ?? }  // Push ebx + Call [??] (sandbox check)
        $pattern1 = { FF 75 08 E8 ?? ?? ?? ?? }  // Push [ebp+08h] + Call [??] (VM check)
        $pattern2 = { 85 C0 0F 84 ?? ?? ?? ?? }  // Test eax + JZ (debugger check)

    condition:
        any of them
}