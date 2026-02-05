rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 53 FF 15 ?? ?? ?? ?? }  // Call to sandbox check (push ebx + call)
        $pattern1 = { 85 C0 0F 84 ?? ?? ?? ?? }  // Test EAX + JZ (early exit check)
        $pattern2 = { FF 75 08 E8 ?? ?? ?? ?? }  // Call to VM check (push ebp+08 + call)

    condition:
        any of them
}