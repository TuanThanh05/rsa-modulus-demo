from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from file_codec import int_to_bytes, int_to_text


def print_recover_plaintext_from_two_parts(value1: int, value2: int, n: int) -> int:
    console = Console()

    recovered_m = (value1 * value2) % n
    recovered_bytes = int_to_bytes(recovered_m)
    recovered_text = int_to_text(recovered_m)

    table = Table(title="Khôi phục bản rõ từ hai giá trị trung gian")

    table.add_column("Bước", justify="right")
    table.add_column("Công thức / Ý nghĩa", justify="left")
    table.add_column("Giá trị", justify="left")

    table.add_row(
        "1",
        "Giá trị 1 = C1^r1 mod N",
        str(value1),
    )

    table.add_row(
        "2",
        "Giá trị 2 = C2^r2 mod N",
        str(value2),
    )

    table.add_row(
        "3",
        "Modulo N",
        str(n),
    )

    table.add_row(
        "4",
        "M = (Giá trị 1 × Giá trị 2) mod N",
        str(recovered_m),
    )

    table.add_row(
        "5",
        "Bản rõ dạng bytes",
        str(recovered_bytes),
    )

    table.add_row(
        "6",
        "Bản rõ dạng text",
        recovered_text,
    )

    console.print(table)

    formula_text = (
        "M = (Giá trị 1 × Giá trị 2) mod N\n"
        f"M = ({value1} × {value2}) mod {n}\n"
        f"M = {recovered_m}\n\n"
        f"Bản rõ = {recovered_text}"
    )

    console.print(
        Panel(
            formula_text,
            title="Kết quả khôi phục bản rõ",
        )
    )

    return recovered_m


def main():
    value1 = 90503433055443266881842270034421863754870546820402116976606320143356892710670548858451213502436441207021400726910834739838145204590847936366950640207086997351932469313716230214949553719952682690159645041013471942629041885770911230866950227851159373553899659323150039745335443245034790895077409463149414727989

    value2 = 100106435594047777657308066356638315223751417802983263755385765086270169879944701787529547766652300616864337332426331901140805028311218868595054825865875985022937579522263013752666346724777819694298067265501157678459276020487908227731452502673839926133821787909866742420435017265091502232952263498172120589380

    n = 112051931469624996066708705428958812565772687807174591034054042863749411011062290213731501199187171399276816429043827377104844167356496601918375525168433323673549787779229518275441099299618601223555540166721263259207962241970768622222035121104111694369871003267174193020868589209882335284250398116813829790163

    print_recover_plaintext_from_two_parts(value1, value2, n)


if __name__ == "__main__":
    main()