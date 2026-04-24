rule IsWindowVisibleTest
{
    meta:
        description = "Detects the test for IsWindowVisible and the conditional jump."
        cape_options = "bp0=$a+0,action0=skip,count=0"
    strings:
        $a = { 85 C0 0F 84 ?? ?? ?? ?? }
    condition:
        $a
}