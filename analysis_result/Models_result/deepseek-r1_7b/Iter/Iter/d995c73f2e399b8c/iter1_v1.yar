rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule - testing various bypass paths"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 74 84 ?? ?? ?? ?? 8B 45 } // TEST EAX + JZ 0F C0 + call
        $pattern1 = { E8 ?? ?? ?? ?? 83 C4 }     // CALL with displacement and stack op
        $pattern2 = { 6A ?? 5A ?? ?? 85 C0 }     // Pushes and pop operations

    condition:
        any of them
}