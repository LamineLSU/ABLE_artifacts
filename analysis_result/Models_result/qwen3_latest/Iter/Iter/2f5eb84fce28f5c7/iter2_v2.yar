rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B }  // Test + je + push (first evasion check)
        $pattern1 = { 85 C0 0F 84 ?? ?? ?? ?? }  // Test + je (second evasion check with offset wildcards)
        $pattern2 = { 85 C0 74 07 50 FF 15 88 A0 0D 01 }  // Test + je + push + call (exit preparation)

    condition:
        any of them
}