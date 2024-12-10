import streamlit as st
import bcrypt
import streamlit_authenticator as stauth
from neo4j import GraphDatabase
import random
import subprocess
import tempfile
import os
from PIL import Image

# ---------------------
# Set Streamlit Page Configuration FIRST
st.set_page_config(page_title="Math Competition Problem Recommender")

# ---------------------
# Database Connection (Adjust as needed)
NEO4J_URI = st.secrets["NEO4J_URI"]
NEO4J_USER = st.secrets["NEO4J_USER"]
NEO4J_PASSWORD = st.secrets["NEO4J_PASSWORD"]

try:
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
except Exception as e:
    st.error(f"❌ Failed to connect to Neo4j: {e}")

# ---------------------
# Database Functions

def create_user(username, password_hash):
    query = """
    CREATE (u:User {username: $username, password_hash: $password_hash})
    RETURN u
    """
    with driver.session() as session:
        session.run(query, username=username, password_hash=password_hash)

def get_user(username):
    query = """
    MATCH (u:User {username:$username})
    RETURN u.username AS username, u.password_hash AS password_hash
    """
    with driver.session() as session:
        res = session.run(query, username=username).single()
        if res:
            return {
                "username": res["username"],
                "password_hash": res["password_hash"]
            }
    return None

def verify_user_credentials(username, password):
    user = get_user(username)
    if user:
        return bcrypt.checkpw(password.encode('utf-8'), user["password_hash"].encode('utf-8'))
    return False

def log_problem_feedback(username, problem_id, feedback_type):
    # feedback_type should be "LIKED" or "DISLIKED"
    query = f"""
    MATCH (u:User {{username:$username}})
    MATCH (p:Problem {{problem_id:$pid}})
    MERGE (u)-[r:{feedback_type}]->(p)
    RETURN r
    """
    with driver.session() as session:
        session.run(query, username=username, pid=problem_id)

def get_user_history(username):
    query = """
    MATCH (u:User {username:$username})-[r]->(p:Problem)
    RETURN p.problem_id as problem_id, TYPE(r) as feedback_type
    ORDER BY p.problem_id
    """
    with driver.session() as session:
        results = session.run(query, username=username).data()
        return results

def get_problem_by_category(category):
    query = """
    MATCH (p:Problem)
    WHERE p.type = $category
    WITH p, rand() as r
    ORDER BY r
    LIMIT 1
    RETURN p.problem_id AS problem_id, p.problem AS problem, p.solution AS solution
    """
    with driver.session() as session:
        res = session.run(query, category=category).single()
        if res:
            return {
                "problem_id": res["problem_id"],
                "problem": res["problem"],
                "solution": res["solution"]
            }
    return None

def get_similar_problems(problem_id):
    query = """
    MATCH (p:Problem {problem_id:$pid})-[:SIMILAR_TO]->(other:Problem)
    RETURN other.problem_id AS problem_id, other.problem AS problem, other.solution AS solution
    ORDER BY rand()
    LIMIT 3
    """
    with driver.session() as session:
        results = session.run(query, pid=problem_id).data()
        return results

def get_another_problem_in_category(category, exclude_id):
    query = """
    MATCH (p:Problem)
    WHERE p.type = $category AND p.problem_id <> $exclude_id
    WITH p, rand() as r
    ORDER BY r
    LIMIT 1
    RETURN p.problem_id AS problem_id, p.problem AS problem, p.solution AS solution
    """
    with driver.session() as session:
        res = session.run(query, category=category, exclude_id=exclude_id).single()
        if res:
            return {
                "problem_id": res["problem_id"],
                "problem": res["problem"],
                "solution": res["solution"]
            }
    return None

# ---------------------
# Asymptote Rendering Functions

def render_asy(asy_code: str) -> Image.Image:
    # Create a temporary .asy file
    with tempfile.NamedTemporaryFile(suffix=".asy", delete=False) as tmp:
        tmp.write(asy_code.encode('utf-8'))
        tmp_name = tmp.name

    png_name = tmp_name.replace(".asy", ".png")

    # Run asy and capture stderr
    result = subprocess.run(["asy", "-o", png_name, tmp_name], capture_output=True, text=True)

    if result.returncode != 0:
        # Asymptote failed. Let's see why.
        st.error("Asymptote error:\n" + result.stderr)
        # Clean up the temporary .asy file since we won't use it.
        os.remove(tmp_name)
        # No png was created, raise an error or return None
        raise RuntimeError("Asymptote failed to produce output. See error above.")

    # If we reach here, png_name should exist
    img = Image.open(png_name)

    # Clean up
    os.remove(tmp_name)
    os.remove(png_name)

    return img

def process_text_with_asy(text: str):
    # Convert LaTeX delimiters
    text = text.replace("\\[", "$$").replace("\\]", "$$")
    text = text.replace("\\begin{align*}", "$$\\begin{aligned}")
    text = text.replace("\\end{align*}", "\\end{aligned}$$")

    start_tag = "[asy]"
    end_tag = "[/asy]"
    parts = []
    start_idx = 0
    while True:
        asy_start = text.find(start_tag, start_idx)
        if asy_start == -1:
            # no more asy tags
            parts.append(text[start_idx:])
            break
        asy_end = text.find(end_tag, asy_start)
        if asy_end == -1:
            # no closing tag found; treat remainder as text
            parts.append(text[start_idx:])
            break

        # Extract text before the asy block
        parts.append(text[start_idx:asy_start])

        # Extract the asy code
        asy_code = text[asy_start+len(start_tag):asy_end].strip()

        # Prepend import line if needed
        # Only do this if you know you always need olympiad.asy
        # If you want to be safe and always have olympiad functions available, do this unconditionally:
        asy_code = "import olympiad;\n" + asy_code

        # Render the asy code to an image
        img = render_asy(asy_code)
        parts.append(img)

        start_idx = asy_end + len(end_tag)

    return parts

# ---------------------
# Logout Function

def logout():
    st.session_state.authenticated = False
    st.session_state.username = None
    st.session_state.category = None
    st.session_state.current_problem = None
    st.success("✅ Logged out successfully!")
    st.rerun()

# ---------------------
# Streamlit UI and State Management

# Initialize session state variables
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
if "username" not in st.session_state:
    st.session_state.username = None
if "category" not in st.session_state:
    st.session_state.category = None
if "current_problem" not in st.session_state:
    st.session_state.current_problem = None

# Authentication section
st.title("Math Competition Problem Recommender")

if not st.session_state.authenticated:
    # Display a login/signup form
    st.header("Login or Sign Up")
    login_tab, signup_tab = st.tabs(["Login", "Sign Up"])

    with login_tab:
        login_username = st.text_input("Username", key="login_username")
        login_password = st.text_input("Password", type="password", key="login_password")
        if st.button("Login"):
            if verify_user_credentials(login_username, login_password):
                st.session_state.authenticated = True
                st.session_state.username = login_username
                st.success("✅ Logged in successfully!")
                st.rerun()
            else:
                st.error("❌ Invalid credentials. Please try again.")

    with signup_tab:
        signup_username = st.text_input("New Username", key="signup_username")
        signup_password = st.text_input("New Password", type="password", key="signup_password")
        if st.button("Sign Up"):
            if get_user(signup_username) is not None:
                st.error("❌ Username already exists. Please choose a different username.")
            else:
                hashed_pw = bcrypt.hashpw(signup_password.encode('utf-8'), bcrypt.gensalt())
                create_user(signup_username, hashed_pw.decode('utf-8'))
                st.success("✅ Account created! Please log in.")
else:
    st.write(f"👋 Hello, **{st.session_state.username}**!")

    # Display User History
    with st.expander("📜 View My History"):
        history = get_user_history(st.session_state.username)
        if history:
            for idx, h in enumerate(history, 1):
                st.write(f"{idx}. **Problem ID**: {h['problem_id']}, **Feedback**: {h['feedback_type']}")
        else:
            st.write("No history yet. Start solving problems to see your history here!")

    st.write("---")  # Separator

    # Category Selection
    if st.session_state.category is None:
        st.subheader("📂 Choose a Category")
        category_choice = st.selectbox(
            "Select the category you're preparing for:",
            ["Algebra", "Geometry", "Number Theory", "Precalculus", "Counting_and_Probability"]
        )
        if st.button("Confirm Category"):
            st.session_state.category = category_choice
            st.success(f"📁 Category set to **{category_choice}**!")
            st.rerun()

    # Fetch a problem if category is selected and no current problem
    if st.session_state.category and st.session_state.current_problem is None:
        prob = get_problem_by_category(st.session_state.category)
        if prob:
            st.session_state.current_problem = prob
            st.rerun()
        else:
            st.error("❌ No problems found for this category.")

    # Display the current problem
    if st.session_state.current_problem:
        st.subheader(f"📝 Problem in {st.session_state.category}")
        st.markdown("**Problem:**")

        # Process problem text
        problem_content = process_text_with_asy(st.session_state.current_problem["problem"])
        for item in problem_content:
            if isinstance(item, str):
                st.markdown(item)
            else:
                st.image(item)

        show_solution = st.checkbox("🔍 Show Solution", key="show_solution")
        if show_solution:
            st.markdown("**Solution:**")
            solution_content = process_text_with_asy(st.session_state.current_problem["solution"])
            for item in solution_content:
                if isinstance(item, str):
                    st.markdown(item)
                else:
                    st.image(item)

        st.write("**Did you find this problem useful?**")
        col1, col2 = st.columns(2)
        with col1:
            if st.button("👍 Yes, I liked it"):
                log_problem_feedback(st.session_state.username, st.session_state.current_problem["problem_id"], "LIKED")
                similar = get_similar_problems(st.session_state.current_problem["problem_id"])
                if similar:
                    st.session_state.current_problem = random.choice(similar)
                    st.success("✅ Great! Here's a similar problem for you.")
                else:
                    st.warning("⚠️ No similar problems found. Selecting another problem from the same category.")
                    next_prob = get_another_problem_in_category(st.session_state.category, st.session_state.current_problem["problem_id"])
                    if next_prob:
                        st.session_state.current_problem = next_prob
                    else:
                        st.error("❌ No other problems found in this category.")
                st.rerun()

        with col2:
            if st.button("👎 Not really"):
                log_problem_feedback(st.session_state.username, st.session_state.current_problem["problem_id"], "DISLIKED")
                next_prob = get_another_problem_in_category(st.session_state.category, st.session_state.current_problem["problem_id"])
                if next_prob:
                    st.session_state.current_problem = next_prob
                    st.success("🔄 Here's another problem for you.")
                else:
                    st.error("❌ No other problems found in this category.")
                st.rerun()

    # Logout Button in Sidebar
    st.sidebar.button("🔒 Logout", on_click=logout)
