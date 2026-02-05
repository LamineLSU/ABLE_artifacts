rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? }  // Test EAX + JZ check
        $pattern1 = { 50 FF 15 ?? ?? ?? ?? 53 FF 15 ?? ?? ?? ?? }  // Push + Call + Push + Call
        $pattern2 = { FF 75 08 FF 15 ?? ?? ?? ?? }  // Push [ebp+08h] + Call

    condition:
        any of them
}