rule EvasionBypass_Patterns {
    meta:
        description = "Detects malware bypass by identifying evasive call sequences"
        cape_options = "$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF ?? 55 ?? EC 8B 4D FC } // Skipping push ebp and moving esp before call
        $pattern1 = { C1 E8 ?? 75 08 59 A1 ?? 01 30 0A 8B 40 68 A8 01 ?? B8 01 18 00 FF 15 AC B0 41 00 } // Skipping jump and call with specific offset
        $pattern2 = { EC F7 08 E8 C8 FF 1E 3C 0A 9B ?? D4 ?? A1 E8 FF 15 3C B0 41 00 } // Skipping complex jump sequence with same offset
}

    condition:
        any of them
}