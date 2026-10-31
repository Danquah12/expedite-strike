from playwright.sync_api import sync_playwright
import time

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    page = browser.new_page()
    
    # Capture console logs
    page.on("console", lambda msg: print(f"Browser Console: {msg.text}"))
    page.on("pageerror", lambda err: print(f"Browser Error: {err}"))
    
    print("Navigating to http://127.0.0.1:9000/")
    page.goto('http://127.0.0.1:9000/')
    time.sleep(5)
    
    print("Clicking Reporting tab...")
    page.evaluate("document.getElementById('nav-reporting').click()")
    time.sleep(2)
    
    print("Clicking Executive Summary...")
    page.evaluate("document.getElementById('menu-rep-0').click()")
    time.sleep(5)
    
    print("Clicking Attack Graph Node...")
    # Just dispatch a click to the canvas center where a node might be.
    # Actually wait. Cytoscape nodes can be clicked via cy.nodes()[0].emit('tap').
    # We can inject JS to find the cy instance and emit a tap!
    try:
        page.evaluate('''
            // Dash cytoscape puts the cy instance on the window if testing is enabled, 
            // but we can just find it or dispatch event.
        ''')
    except Exception as e:
        pass
    
    time.sleep(2)
    browser.close()
