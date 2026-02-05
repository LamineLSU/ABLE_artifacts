rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule for detecting obfuscated control flow or anti-analysis patterns"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 8D 95 F0 FE FF FF }  // First check: test, je, and lea
        $pattern1 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? }  // Second check: test, je (offset wildcard), and mov
        $pattern2 = { 85 C0 0F 84 ?? ?? ?? ?? E8 ?? ?? ?? ?? }  // Third check: test, je (offset wildcard), and call

    condition: all of them
}