rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B 5A 8B CE E8 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? }  // Test/Je/Call sequence from TRACE //1
        $pattern1 = { 55 8B EC FF 75 08 E8 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? }                // Push/Call sequence from TRACE //3
        $pattern2 = { 8B FF 55 8B EC E8 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? }                  // Test/Call sequence from TRACE //5

    condition:
        any of them
}