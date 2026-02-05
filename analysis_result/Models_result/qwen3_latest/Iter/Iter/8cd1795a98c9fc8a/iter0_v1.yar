rule ConditionalMemoryAccess
{
    meta:
        description = "Conditional check and memory load"
        cape_options = "bp0=$s1+0,action0=skip,count=0"
    strings:
        $s1 = { 83 F8 01 74 ?? 64 A1 ?? ?? ?? ?? }
    condition:
        $s1
}