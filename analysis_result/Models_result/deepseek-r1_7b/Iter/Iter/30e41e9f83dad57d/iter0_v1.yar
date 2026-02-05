rule Bypass_Sample
{
    meta:
        description = "Evasion bypass using conditional jumps and function calls"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 5E 8B CE E8 ?? > ?? > ?? > ?? > ?? > ?? > } // Example pattern: Testing EAX and jumping
        $pattern1 = { 6A ?? 5A 8B CE E8 ?? > ?? > ?? > ?? > ?? > ?? > } // Another bypass path using PUSH and POP
        $pattern2 = { FF 15 BC 36 61 00 ?? > ?? > ?? > ?? > ?? > ?? > } // Third bypass candidate with specific offset
    condition:
        any of them
}