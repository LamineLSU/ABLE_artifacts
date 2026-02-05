rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 ?? 6A 5B }  // Test+je+push sequence from TRACE //1
        $pattern1 = { FF 15 ?? ?? ?? ?? }  // Exit call (call dword ptr) from TRACE //1
        $pattern2 = { 85 C0 0F 84 ?? ?? ?? ?? }  // Test+je with offset from TRACE //1

    condition:
        any of them
}