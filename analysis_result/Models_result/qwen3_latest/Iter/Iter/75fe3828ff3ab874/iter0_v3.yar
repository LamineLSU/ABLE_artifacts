rule Pattern1
{
    meta:
        description = "Conditional jump after test eax, eax (first check)"
        cape_options = "bp0=$a+0,action0=skip,count=0"
    strings:
        $a = { 85 C0 75 ?? 8B 45 ?? }
    condition:
        $a
}