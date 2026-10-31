from playwright.sync_api import sync_playwright
import time

def run():
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()
        
        errors = []
        page.on("pageerror", lambda err: errors.append(f"Page Error: {err}"))
        page.on("console", lambda msg: errors.append(f"Console {msg.type}: {msg.text}") if msg.type == "error" else None)
        
        print("Navigating to http://127.0.0.1:9000/")
        page.goto("http://127.0.0.1:9000/")
        
        print("Waiting for network...")
        page.wait_for_load_state("networkidle")
        
        # Click the tab using Javascript to bypass visibility
        print("Clicking menu-rep-0 (1. Executive Summary) via JS...")
        page.evaluate("document.getElementById('menu-rep-0').click()")
        time.sleep(2)
        
        print("Clicking a Cytoscape location...")
        # Since Cytoscape canvas intercepts clicks, we click in the middle of it
        page.mouse.click(330, 500)
        time.sleep(2)
        
        print("Clicking Risk Severity pie chart location...")
        page.mouse.click(250, 950)
        time.sleep(2)
        
        print("Collected Errors:")
        for e in errors:
            print(e)
            
        browser.close()

if __name__ == "__main__":
    run()
