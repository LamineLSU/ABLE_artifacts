rule Bypass_Sample
{
    meta:
        description = "Evasion bypass patterns targeting specific address instructions"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? 7E 5B ?? }  // TEST EAX with offset
        $pattern1 = { E8 C7 F8 8A ?? ?? 83 C4 85 }  // JAE or call with displacement
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? ?? ?? }  // PUSH, POP, and CALL sequence

    condition:
        any of them
}