rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 74 20 8B FF 55 8B EC 83 EC 18 } // cmp eax, 01h; je 004448BCh
        $pattern1 = { 75 08 6A 00 6A 00 FF 15 40 30 40 00 } // cmp eax, 000000B7h; jne 00401A16h
        $pattern2 = { 85 C0 75 0E 56 8D 85 F8 FD FF FF } // test eax, eax; je 004012D8h

    condition:
        any of them
}