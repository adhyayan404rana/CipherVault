"""Compact dashboard presentation; no cryptographic behavior lives here."""
CSS = """
<style>
.stApp { background: #0b101b; }
.stAppHeader { background: transparent; }
[data-testid="stToolbar"], #MainMenu, footer { display: none; }
[data-testid="stMainBlockContainer"] { padding: 2rem 2.2rem 3rem; max-width: 1500px; }
[data-testid="stSidebar"] { background: #101827; min-width: 230px !important; max-width: 230px !important; border-right: 1px solid #223047; }
[data-testid="stSidebarUserContent"] { padding: 1.8rem 1rem; }
[data-testid="stSidebar"] [role="radiogroup"] { gap: 5px; }
[data-testid="stSidebar"] [role="radiogroup"] label { padding: 9px 12px; border-radius: 8px; width: 100%; }
[data-testid="stSidebar"] [role="radiogroup"] label:has(input:checked) { background: #173449; color: #67d4fb; }
[data-testid="stSidebar"] [data-testid="stRadioOption"] > div > div:first-child { display: none !important; }
[data-testid="stSidebar"] [role="radiogroup"] > div { width: 100%; }
[data-testid="stSidebar"] [role="radiogroup"] label[data-focus-visible] { outline: 2px solid #67d4fb; outline-offset: 2px; }
h1 { font-size: 1.8rem !important; letter-spacing: -.04em; padding: 0 0 .35rem !important; }
h2 { font-size: 1.25rem !important; } h3 { font-size: 1.05rem !important; }
[data-testid="stMetric"] { background: #121d2d; border: 1px solid #243248; border-radius: 12px; padding: 16px 18px; }
[data-testid="stMetricValue"] { font-size: 1.6rem; }
[data-testid="stMetricLabel"] { color: #95a7bf; }
[data-testid="stVerticalBlockBorderWrapper"] > div { border-radius: 12px !important; border-color: #253247 !important; }
.stButton button, .stDownloadButton button { border-radius: 8px; min-height: 40px; }
.stButton button[kind="primary"] { color: #071521; font-weight: 600; }
[data-testid="stFileUploader"] { border-radius: 10px; }
[data-testid="stTabs"] [role="tablist"] { gap: 20px; border-bottom: 1px solid #253247; margin-bottom: 16px; }
[data-testid="stCode"] { font-size: .8rem; }
.brand { display: flex; align-items: center; gap: 10px; font-size: 21px; font-weight: 750; letter-spacing: -.6px; margin-bottom: 4px; }
.brand-mark { background: #38bdf8; color: #091622; border-radius: 9px; width: 30px; height: 30px; display: grid; place-items: center; font-size: 16px; }
.brand-sub { font-size: 11px; color: #7f94ae; letter-spacing: 1.8px; margin: 0 0 30px 40px; }
.status-pill { display: inline-block; border: 1px solid #29443e; background: #132b25; color: #83ddba; padding: 6px 10px; font-size: 12px; border-radius: 20px; }
.section-kicker { color: #67d4fb; font-size: 11px; letter-spacing: 1.6px; text-transform: uppercase; margin-bottom: 6px; }
.tool-icon { color: #67d4fb; font-size: 22px; margin-bottom: 8px; }
.empty-chart { min-height: 155px; display: flex; flex-direction: column; justify-content: center; align-items: center; border: 1px dashed #304057; border-radius: 10px; background: linear-gradient(180deg,#132032,#0f1826); text-align: center; color: #8ca1bc; gap: 10px; margin: 12px 0; }
.empty-chart strong { color: #c9d5e5; font-size: 15px; }.empty-chart span { font-size: 12px; }
.activity-row { padding: 13px 0; border-bottom: 1px solid #253247; font-size: 13px; }
.activity-row strong { display: block; color: #dce6f4; }.activity-row span { color: #90a4bd; font-size: 12px; }
@media(max-width: 850px) { [data-testid="stMainBlockContainer"] { padding: 1.5rem 1rem; } [data-testid="stMetricValue"] { font-size: 1.2rem; } }
</style>
"""
