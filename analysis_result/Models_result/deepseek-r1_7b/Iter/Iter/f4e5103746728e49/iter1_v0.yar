rule Bypass_Evasion
{
    meta:
        description = "Evasion bypass patterns targeting specific code paths"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? }  // TEST EAX with JZ and nearby instructions
        $pattern1 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }  // PUSH/POP with conditional jump
        $pattern2 = { E8 ?? ?? ?? ?? FF 75 ?? FF 1F ?? }    // CALL with offset and stack manipulation

    condition:
        any of them
}