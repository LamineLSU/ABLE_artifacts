rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 00 A2 61 7C 85 C0 00 A2 61 7E 6A 5B 00 A2 61 80 5A }  // TEST EAX followed by JE
        $pattern1 = { 00 A2 61 83 E8 25 05 00 00 A2 61 85 0F 84 33 FD FF FF }   // JCMP+JE (specific offset)
        $pattern2 = { 00 A2 61 7A 8B CE 00 A2 61 7C EA 00 A2 61 7E }  // Another TEST/PUSH pattern

    condition:
        any of them
}