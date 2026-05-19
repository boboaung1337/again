#!/usr/bin/env python3
"""
Micro-blog Publishing Platform - Like Telegra.ph
Usage: python3 blog.py [port]
"""

import os
import sys
import json
import re
import datetime
import urllib.parse
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
import html

class Config:
    PORT = 8080
    DATA_DIR = Path("./blog_posts")
    SITE_TITLE = "Micro Blog"
    SITE_DESC = "Publish instantly, no account needed"
    BASE_URL = "http://localhost:8080"

class BlogHandler(BaseHTTPRequestHandler):
    
    def log_message(self, format, *args):
        print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] {args[0] if args else format}")
    
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        
        if parsed.path == '/':
            self.serve_home()
        elif parsed.path == '/new':
            self.serve_editor()
        elif parsed.path == '/about':
            self.serve_about()
        elif parsed.path.startswith('/post/'):
            self.serve_post(parsed.path[6:])
        elif parsed.path == '/api/posts':
            self.api_list_posts()
        else:
            self.serve_404()
    
    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        
        if parsed.path == '/api/create':
            self.api_create_post()
        elif parsed.path == '/api/delete':
            self.api_delete_post()
        else:
            self.send_json({'error': 'Not found'}, 404)
    
    def serve_home(self):
        """Serve homepage with recent posts"""
        posts = self.get_all_posts()
        
        html_content = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{Config.SITE_TITLE}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Georgia', 'Times New Roman', serif;
            background: #fafaf8;
            color: #1a1a1a;
            line-height: 1.6;
        }}
        
        .container {{
            max-width: 800px;
            margin: 0 auto;
            padding: 40px 24px;
        }}
        
        .header {{
            text-align: center;
            margin-bottom: 60px;
            border-bottom: 1px solid #eaeaea;
            padding-bottom: 40px;
        }}
        
        .header h1 {{
            font-size: 3rem;
            font-weight: 400;
            letter-spacing: -0.02em;
            margin-bottom: 12px;
        }}
        
        .header p {{
            color: #6b6b6b;
            font-size: 1.1rem;
        }}
        
        .new-post-btn {{
            display: inline-block;
            background: #1a1a1a;
            color: white;
            text-decoration: none;
            padding: 12px 28px;
            border-radius: 40px;
            margin-top: 24px;
            font-size: 0.95rem;
            transition: all 0.2s;
        }}
        
        .new-post-btn:hover {{
            background: #333;
            transform: translateY(-2px);
        }}
        
        .post-list {{
            margin-bottom: 60px;
        }}
        
        .post-item {{
            margin-bottom: 48px;
            padding-bottom: 48px;
            border-bottom: 1px solid #eaeaea;
        }}
        
        .post-title {{
            font-size: 1.8rem;
            font-weight: 400;
            margin-bottom: 12px;
        }}
        
        .post-title a {{
            color: #1a1a1a;
            text-decoration: none;
        }}
        
        .post-title a:hover {{
            color: #4a4a4a;
        }}
        
        .post-meta {{
            color: #8a8a8a;
            font-size: 0.85rem;
            margin-bottom: 16px;
            font-family: monospace;
        }}
        
        .post-excerpt {{
            color: #3a3a3a;
            line-height: 1.7;
        }}
        
        .read-more {{
            display: inline-block;
            margin-top: 12px;
            color: #1a1a1a;
            text-decoration: none;
            font-size: 0.9rem;
        }}
        
        .read-more:hover {{
            text-decoration: underline;
        }}
        
        .footer {{
            text-align: center;
            padding: 40px 0;
            color: #8a8a8a;
            font-size: 0.85rem;
            border-top: 1px solid #eaeaea;
        }}
        
        @media (max-width: 640px) {{
            .container {{ padding: 24px 20px; }}
            .header h1 {{ font-size: 2rem; }}
            .post-title {{ font-size: 1.4rem; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{Config.SITE_TITLE}</h1>
            <p>{Config.SITE_DESC}</p>
            <a href="/new" class="new-post-btn">✍️ Write something</a>
        </div>
        
        <div class="post-list" id="postList">
            <div style="text-align: center; padding: 40px;">Loading posts...</div>
        </div>
        
        <div class="footer">
            <p>simple. instant. anonymous.</p>
        </div>
    </div>
    
    <script>
        async function loadPosts() {{
            try {{
                const res = await fetch('/api/posts');
                const posts = await res.json();
                renderPosts(posts);
            }} catch (err) {{
                console.error(err);
            }}
        }}
        
        function renderPosts(posts) {{
            const container = document.getElementById('postList');
            
            if (posts.length === 0) {{
                container.innerHTML = '<div style="text-align: center; padding: 60px 20px; color: #b0b0b0;">— no posts yet —<br><a href="/new" style="color: #1a1a1a;">create the first one</a></div>';
                return;
            }}
            
            container.innerHTML = posts.map(post => `
                <div class="post-item">
                    <h2 class="post-title">
                        <a href="${post.url}">${escapeHtml(post.title)}</a>
                    </h2>
                    <div class="post-meta">
                        ${post.date} · {post.views} views
                    </div>
                    <div class="post-excerpt">
                        ${post.excerpt}
                    </div>
                    <a href="${post.url}" class="read-more">Continue reading →</a>
                </div>
            `).join('');
        }}
        
        function escapeHtml(text) {{
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }}
        
        loadPosts();
    </script>
</body>
</html>'''
        
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        self.wfile.write(html_content.encode())
    
    def serve_editor(self):
        """Serve post editor"""
        # Get the actual base URL from request
        host = self.headers.get('Host', f'localhost:{Config.PORT}')
        base_url = f"http://{host}"
        
        html_content = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>New Post - Micro Blog</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Georgia', serif;
            background: #fafaf8;
            color: #1a1a1a;
        }}
        
        .container {{
            max-width: 900px;
            margin: 0 auto;
            padding: 40px 24px;
        }}
        
        .header {{
            margin-bottom: 40px;
        }}
        
        .back-link {{
            color: #6b6b6b;
            text-decoration: none;
            font-size: 0.9rem;
        }}
        
        .back-link:hover {{
            color: #1a1a1a;
        }}
        
        h1 {{
            font-size: 2rem;
            font-weight: 400;
            margin: 20px 0;
        }}
        
        .form-group {{
            margin-bottom: 24px;
        }}
        
        label {{
            display: block;
            margin-bottom: 8px;
            font-weight: 500;
            color: #1a1a1a;
        }}
        
        input[type="text"],
        textarea {{
            width: 100%;
            padding: 12px;
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            font-size: 1rem;
            font-family: inherit;
            transition: all 0.2s;
        }}
        
        input[type="text"]:focus,
        textarea:focus {{
            outline: none;
            border-color: #1a1a1a;
        }}
        
        textarea {{
            min-height: 400px;
            resize: vertical;
            line-height: 1.6;
        }}
        
        .submit-btn {{
            background: #1a1a1a;
            color: white;
            border: none;
            padding: 12px 28px;
            border-radius: 40px;
            font-size: 1rem;
            cursor: pointer;
            transition: all 0.2s;
        }}
        
        .submit-btn:hover {{
            background: #333;
            transform: translateY(-2px);
        }}
        
        .status {{
            margin-top: 20px;
            padding: 12px;
            border-radius: 8px;
            display: none;
        }}
        
        .status.success {{
            background: #d4edda;
            color: #155724;
            display: block;
        }}
        
        .status.error {{
            background: #f8d7da;
            color: #721c24;
            display: block;
        }}
        
        .url-box {{
            margin-top: 20px;
            padding: 16px;
            background: #f5f5f5;
            border-radius: 8px;
            display: none;
            word-break: break-all;
        }}
        
        .url-box.show {{
            display: block;
        }}
        
        .url-label {{
            font-size: 0.85rem;
            color: #6b6b6b;
            margin-bottom: 8px;
        }}
        
        .url {{
            font-family: monospace;
            font-size: 0.9rem;
            color: #1a1a1a;
            background: white;
            padding: 8px;
            border-radius: 4px;
            margin: 8px 0;
        }}
        
        .copy-btn {{
            background: #1a1a1a;
            color: white;
            border: none;
            padding: 6px 12px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 0.8rem;
        }}
        
        .copy-btn:hover {{
            background: #333;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <a href="/" class="back-link">← back</a>
            <h1>Write something</h1>
        </div>
        
        <form id="postForm">
            <div class="form-group">
                <label>Title</label>
                <input type="text" id="title" placeholder="untitled" autocomplete="off">
            </div>
            
            <div class="form-group">
                <label>Content (markdown supported)</label>
                <textarea id="content" placeholder="Write your post here..."></textarea>
            </div>
            
            <button type="submit" class="submit-btn">Publish →</button>
        </form>
        
        <div id="status" class="status"></div>
        <div id="urlBox" class="url-box">
            <div class="url-label">✨ Your post is live at:</div>
            <div class="url" id="postUrl"></div>
            <button class="copy-btn" onclick="copyUrl()">Copy link</button>
            <div style="margin-top: 12px;">
                <a href="/" class="back-link">→ back to home</a>
            </div>
        </div>
    </div>
    
    <script>
        let currentPostUrl = '';
        
        document.getElementById('postForm').onsubmit = async (e) => {{
            e.preventDefault();
            
            const title = document.getElementById('title').value.trim();
            const content = document.getElementById('content').value;
            
            if (!content) {{
                showStatus('Content cannot be empty', 'error');
                return;
            }}
            
            try {{
                const res = await fetch('/api/create', {{
                    method: 'POST',
                    headers: {{ 'Content-Type': 'application/json' }},
                    body: JSON.stringify({{ 
                        title: title || 'Untitled', 
                        content: content 
                    }})
                }});
                
                const data = await res.json();
                
                if (data.success) {{
                    currentPostUrl = data.url;
                    document.getElementById('postUrl').innerHTML = `<a href="${{data.url}}" target="_blank">${{data.url}}</a>`;
                    document.getElementById('urlBox').classList.add('show');
                    document.getElementById('postForm').style.display = 'none';
                    showStatus('Published!', 'success');
                }} else {{
                    showStatus(data.error || 'Failed to publish', 'error');
                }}
            }} catch (err) {{
                showStatus('Network error', 'error');
            }}
        }};
        
        function showStatus(msg, type) {{
            const status = document.getElementById('status');
            status.textContent = msg;
            status.className = `status ${{type}}`;
            setTimeout(() => {{
                status.className = 'status';
            }}, 3000);
        }}
        
        function copyUrl() {{
            navigator.clipboard.writeText(currentPostUrl);
            showStatus('Link copied!', 'success');
        }}
    </script>
</body>
</html>'''
        
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        self.wfile.write(html_content.encode())
    
    def serve_post(self, slug):
        """Serve individual post"""
        post = self.get_post(slug)
        
        if not post:
            self.serve_404()
            return
        
        # Increment view count
        self.increment_views(slug)
        post['views'] += 1
        
        html_content = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{html.escape(post['title'])} - Micro Blog</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Georgia', serif;
            background: #fafaf8;
            color: #1a1a1a;
            line-height: 1.7;
        }}
        
        .container {{
            max-width: 800px;
            margin: 0 auto;
            padding: 60px 24px;
        }}
        
        .back-link {{
            display: inline-block;
            margin-bottom: 40px;
            color: #6b6b6b;
            text-decoration: none;
        }}
        
        .back-link:hover {{
            color: #1a1a1a;
        }}
        
        .post-title {{
            font-size: 2.5rem;
            font-weight: 400;
            margin-bottom: 16px;
            line-height: 1.2;
        }}
        
        .post-meta {{
            color: #8a8a8a;
            font-size: 0.85rem;
            margin-bottom: 40px;
            font-family: monospace;
            padding-bottom: 20px;
            border-bottom: 1px solid #eaeaea;
        }}
        
        .post-content {{
            font-size: 1.1rem;
            margin-bottom: 60px;
        }}
        
        .post-content p {{
            margin-bottom: 1.5em;
        }}
        
        .footer {{
            text-align: center;
            padding: 40px 0;
            color: #8a8a8a;
            font-size: 0.85rem;
            border-top: 1px solid #eaeaea;
        }}
        
        @media (max-width: 640px) {{
            .container {{ padding: 40px 20px; }}
            .post-title {{ font-size: 1.8rem; }}
            .post-content {{ font-size: 1rem; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <a href="/" class="back-link">← back</a>
        
        <article>
            <h1 class="post-title">{html.escape(post['title'])}</h1>
            <div class="post-meta">
                {post['date']} · {post['views']} views
            </div>
            <div class="post-content">
                {self.format_content(post['content'])}
            </div>
        </article>
        
        <div class="footer">
            <p><a href="/new" style="color: #1a1a1a;">write your own</a> · published on micro.blog</p>
        </div>
    </div>
</body>
</html>'''
        
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        self.wfile.write(html_content.encode())
    
    def serve_about(self):
        """Serve about page"""
        html_content = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>About - Micro Blog</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Georgia', serif;
            background: #fafaf8;
            color: #1a1a1a;
            line-height: 1.7;
        }
        .container {
            max-width: 700px;
            margin: 0 auto;
            padding: 60px 24px;
        }
        .back-link {
            display: inline-block;
            margin-bottom: 40px;
            color: #6b6b6b;
            text-decoration: none;
        }
        h1 {
            font-size: 2rem;
            font-weight: 400;
            margin-bottom: 24px;
        }
        p {
            margin-bottom: 1.5em;
            color: #3a3a3a;
        }
    </style>
</head>
<body>
    <div class="container">
        <a href="/" class="back-link">← back</a>
        <h1>About</h1>
        <p>A minimalist publishing platform. No accounts, no tracking, no complexity.</p>
        <p>Write something, get a link, share it. That's it.</p>
        <p>Inspired by Telegra.ph — simple, fast, anonymous.</p>
    </div>
</body>
</html>'''
        
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        self.wfile.write(html_content.encode())
    
    def serve_404(self):
        self.send_response(404)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        self.wfile.write(b'<h1>404 - Not Found</h1>')
    
    def api_list_posts(self):
        """List all posts"""
        posts = self.get_all_posts()
        self.send_json(posts)
    
    def api_create_post(self):
        """Create a new post with slug-based URL"""
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length)
        
        try:
            data = json.loads(body)
            title = data.get('title', 'Untitled')
            content = data.get('content', '')
            
            if not content.strip():
                self.send_json({'error': 'Content is required'}, 400)
                return
            
            # Create slug from title (human-readable)
            slug = self.create_slug(title)
            
            # Make sure slug is unique
            original_slug = slug
            counter = 1
            while (Config.DATA_DIR / f"{slug}.json").exists():
                slug = f"{original_slug}-{counter}"
                counter += 1
            
            # Get base URL from request
            host = self.headers.get('Host', f'localhost:{Config.PORT}')
            base_url = f"http://{host}"
            post_url = f"{base_url}/post/{slug}"
            
            # Save post
            post = {
                'id': slug,
                'slug': slug,
                'title': title[:200],
                'content': content,
                'date': datetime.datetime.now().strftime('%B %d, %Y'),
                'timestamp': datetime.datetime.now().isoformat(),
                'views': 0,
                'url': post_url
            }
            
            Config.DATA_DIR.mkdir(exist_ok=True)
            with open(Config.DATA_DIR / f"{slug}.json", 'w') as f:
                json.dump(post, f, indent=2)
            
            self.send_json({
                'success': True, 
                'id': slug,
                'url': post_url,
                'slug': slug
            })
            
        except Exception as e:
            self.send_json({'error': str(e)}, 500)
    
    def create_slug(self, title):
        """Create URL-friendly slug from title"""
        # Convert to lowercase
        slug = title.lower()
        # Replace spaces with hyphens
        slug = re.sub(r'\s+', '-', slug)
        # Remove special characters
        slug = re.sub(r'[^\w\-]', '', slug)
        # Remove multiple hyphens
        slug = re.sub(r'-+', '-', slug)
        # Trim hyphens
        slug = slug.strip('-')
        # If empty, use timestamp
        if not slug:
            slug = datetime.datetime.now().strftime('post-%Y%m%d-%H%M%S')
        return slug
    
    def api_delete_post(self):
        """Delete a post"""
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length)
        
        try:
            data = json.loads(body)
            slug = data.get('slug')
            
            if not slug:
                self.send_json({'error': 'Slug required'}, 400)
                return
            
            post_file = Config.DATA_DIR / f"{slug}.json"
            if post_file.exists():
                post_file.unlink()
                self.send_json({'success': True})
            else:
                self.send_json({'error': 'Post not found'}, 404)
                
        except Exception as e:
            self.send_json({'error': str(e)}, 500)
    
    def get_all_posts(self):
        """Get all posts sorted by date"""
        Config.DATA_DIR.mkdir(exist_ok=True)
        
        # Get base URL from request context (fallback)
        host = getattr(self, 'host_header', f'localhost:{Config.PORT}')
        base_url = f"http://{host}"
        
        posts = []
        for file in Config.DATA_DIR.glob('*.json'):
            with open(file, 'r') as f:
                post = json.load(f)
                # Create excerpt
                content_clean = post['content'][:200].replace('\n', ' ')
                post['excerpt'] = content_clean + ('...' if len(post['content']) > 200 else '')
                post['url'] = f"{base_url}/post/{post['slug']}"
                posts.append(post)
        
        # Sort by date (newest first)
        posts.sort(key=lambda x: x['timestamp'], reverse=True)
        return posts
    
    def get_post(self, slug):
        """Get single post by slug"""
        post_file = Config.DATA_DIR / f"{slug}.json"
        if not post_file.exists():
            return None
        
        with open(post_file, 'r') as f:
            post = json.load(f)
            # Add URL
            host = self.headers.get('Host', f'localhost:{Config.PORT}')
            post['url'] = f"http://{host}/post/{slug}"
            return post
    
    def increment_views(self, slug):
        """Increment view count"""
        post_file = Config.DATA_DIR / f"{slug}.json"
        if post_file.exists():
            with open(post_file, 'r') as f:
                post = json.load(f)
            post['views'] += 1
            with open(post_file, 'w') as f:
                json.dump(post, f, indent=2)
    
    def format_content(self, content):
        """Format content with basic markdown"""
        lines = content.split('\n')
        html_lines = []
        
        for line in lines:
            # Headers
            if line.startswith('# '):
                html_lines.append(f'<h1>{html.escape(line[2:])}</h1>')
            elif line.startswith('## '):
                html_lines.append(f'<h2>{html.escape(line[3:])}</h2>')
            elif line.startswith('### '):
                html_lines.append(f'<h3>{html.escape(line[4:])}</h3>')
            # Links
            elif '[' in line and '](' in line:
                import re
                line = re.sub(r'\[([^\]]+)\]\(([^\)]+)\)', r'<a href="\2">\1</a>', line)
                html_lines.append(f'<p>{html.escape(line)}</p>')
            # Empty line
            elif not line.strip():
                html_lines.append('')
            # Paragraph
            else:
                html_lines.append(f'<p>{html.escape(line)}</p>')
        
        return '\n'.join(html_lines)
    
    def send_json(self, data, status=200):
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

def main():
    if len(sys.argv) > 1:
        try:
            Config.PORT = int(sys.argv[1])
        except:
            pass
    
    Config.DATA_DIR.mkdir(exist_ok=True)
    
    server = HTTPServer(('0.0.0.0', Config.PORT), BlogHandler)
    
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        local_ip = s.getsockname()[0]
        s.close()
    except:
        local_ip = '127.0.0.1'
    
    print("\n" + "="*60)
    print(f"📝 {Config.SITE_TITLE} - Publishing Platform")
    print("="*60)
    print(f"✓ Server: http://{local_ip}:{Config.PORT}")
    print(f"✓ Posts stored in: {Config.DATA_DIR}")
    print("="*60)
    print("\n✨ Features:")
    print("   • Human-readable URLs (based on title)")
    print("   • Copy link after publishing")
    print("   • No login required")
    print("   • Instant sharing")
    print("\n🌐 Open in browser:")
    print(f"   http://localhost:{Config.PORT}")
    print(f"   http://{local_ip}:{Config.PORT}")
    print("\n📝 Example URLs:")
    print(f"   http://{local_ip}:{Config.PORT}/post/my-awesome-post")
    print("\nPress Ctrl+C to stop\n")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n🛑 Server stopped\n")

if __name__ == '__main__':
    main()
