rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting sample calls"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 75 0C F7 25 00 ?? } // Conditional jump near (JZ) leading to E8F7...
        $pattern1 = { 74 3A ?? 45 C0 }   // JZ with offset followed by a call
        $pattern2 = { 6A ?? 5A F7 25 ?? } // Another bypass pattern involving mov and jump

    condition:
        any of them
}