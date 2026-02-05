rule Bypass_Evasion_Patterns
{
    meta:
        description = "Evasion bypass detection for exit process"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 74 ?? ?? ?? ?? 83 C4 ?? 85 C0 0F 84 ?? ?? ?? ?? } // Example pattern for TEST JZ
        $pattern1 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 } // Example pattern combining LEA and conditional jump
        $pattern2 = { BA 0F 8B 47 3E 8D 4D FC 83 C4 85 C1 } // Example stack manipulation pattern

    condition:
        any of them
}