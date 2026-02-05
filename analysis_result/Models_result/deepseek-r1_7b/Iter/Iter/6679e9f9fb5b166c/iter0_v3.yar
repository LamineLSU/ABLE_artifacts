rule Bypass_Evasion
{
    meta:
        description = "Evasion bypass patterns targeting exit codes, return addresses, and displacements."
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 5A 8B CE E8 C6 ?? ?? 8D 95 80 FD FF FF 33 C0 }
        $pattern1 = { 8B 45 5A 8B CE E8 D2 ?? ?? 8D 95 88 FD FF FF }
                      E8D6CCFFFF       }
        $pattern2 = { 8B 45 5A 8B CE E8 ED FF 8D 95 8C FD FF FF }
                      BA09000000       }
    condition:
        any of them
}