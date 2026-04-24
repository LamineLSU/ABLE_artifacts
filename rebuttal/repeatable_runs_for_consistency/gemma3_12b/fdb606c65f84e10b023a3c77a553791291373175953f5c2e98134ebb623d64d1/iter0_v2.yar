rule Bypass_Sample
{
    meta:
        description = "Call bypass after memory access (trace 2)"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern2 = { A1 88 85 0C 85 C0 0F 84 33 FD FF FF 0F 84 33 FD FF FF }
        // A1 88 85 0C: mov eax, dword ptr [000C8588h]
        // 85 C0: test eax, eax
        // 0F 84 33 FD FF FF: je 000C5E83h
        // 0F 84 33 FD FF FF: je 000C5E83h
    condition:
        any of them
}