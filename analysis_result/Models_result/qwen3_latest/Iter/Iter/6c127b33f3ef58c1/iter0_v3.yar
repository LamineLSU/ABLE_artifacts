rule bypass_first_check
{
    meta:
        description = "Detects a conditional check using cmp and je instructions"
        cape_options = "bp0=$a+0,action0=skip,count=0"
    strings:
        $a = { 83 F8 01 74 ?? ?? ?? }
    condition:
        $a
}