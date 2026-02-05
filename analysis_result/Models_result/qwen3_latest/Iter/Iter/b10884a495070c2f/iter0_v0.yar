rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 C4 04 90 FF 15 ?? ?? ?? ?? }  // ExitProcess call with surrounding context
        $pattern1 = { 8B 45 08 50 53 E8 ?? ?? ?? ?? }  // Indirect call to 004012C0h with push setup
        $pattern2 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? }  // Push + call to 004015A0h with address wildcards

    condition:
        any of them
}