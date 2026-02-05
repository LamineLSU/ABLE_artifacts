rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved with multiple strategies"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 89 45 FC DD EB 04 EA }
                     83F811         cmp eax, 11h                      }
                     7405             je 00401027h                    }

    $pattern1 = { 83 A5 94 FE FF FF 00 AD DD EB 00 00 01 6C 00 00 00 00 83 A5 98 FE FF FF 00 AD DD EB 00 00 01 68 00 00 00 00 C7 85 9C FE FF FF AC 77 44 00 DD EB 00 00 01 64 00 44 77 AC }

    $pattern2 = { FC CD 5B EB 68 C0 41 C8 17 17 C8 41 C0 FF 75 FC DD EB 04 90 83 65 FC 00 AD DD EB 04 00 00 00 00 }

    condition:
        any of them
}