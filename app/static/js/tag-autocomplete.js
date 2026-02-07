/**
 * Tag Autocomplete
 * Provides autocomplete suggestions for tag input fields
 */

class TagAutocomplete {
    constructor(inputElement, options = {}) {
        this.input = inputElement;
        this.options = {
            minChars: 1,
            maxResults: 10,
            apiUrl: '/api/tags/search',
            delay: 300,
            ...options
        };

        this.dropdown = null;
        this.selectedIndex = -1;
        this.searchTimeout = null;
        this.currentTags = [];

        this.init();
    }

    init() {
        // Create dropdown element
        this.createDropdown();

        // Bind event listeners
        this.input.addEventListener('input', this.handleInput.bind(this));
        this.input.addEventListener('keydown', this.handleKeydown.bind(this));
        this.input.addEventListener('focus', this.handleFocus.bind(this));

        // Close dropdown when clicking outside
        document.addEventListener('click', (e) => {
            if (!this.input.contains(e.target) && !this.dropdown.contains(e.target)) {
                this.hideDropdown();
            }
        });
    }

    createDropdown() {
        this.dropdown = document.createElement('div');
        this.dropdown.className = 'tag-autocomplete-dropdown';
        this.dropdown.style.cssText = `
            position: absolute;
            z-index: 1000;
            background: white;
            border: 1px solid #ced4da;
            border-radius: 0.25rem;
            box-shadow: 0 2px 8px rgba(0,0,0,0.15);
            max-height: 200px;
            overflow-y: auto;
            display: none;
            min-width: 200px;
        `;

        // Insert dropdown after input
        this.input.parentNode.style.position = 'relative';
        this.input.parentNode.appendChild(this.dropdown);
    }

    handleInput(e) {
        clearTimeout(this.searchTimeout);

        const value = this.getCurrentWord();

        if (value.length >= this.options.minChars) {
            this.searchTimeout = setTimeout(() => {
                this.search(value);
            }, this.options.delay);
        } else {
            this.hideDropdown();
        }
    }

    handleKeydown(e) {
        if (!this.dropdown.style.display || this.dropdown.style.display === 'none') {
            return;
        }

        switch (e.key) {
            case 'ArrowDown':
                e.preventDefault();
                this.selectNext();
                break;
            case 'ArrowUp':
                e.preventDefault();
                this.selectPrevious();
                break;
            case 'Enter':
                e.preventDefault();
                if (this.selectedIndex >= 0) {
                    this.selectTag(this.selectedIndex);
                }
                break;
            case 'Escape':
                this.hideDropdown();
                break;
        }
    }

    handleFocus() {
        // Show recent tags when focusing empty field
        const value = this.input.value.trim();
        if (!value) {
            this.search('');
        }
    }

    getCurrentWord() {
        const value = this.input.value;
        const cursorPos = this.input.selectionStart;

        // Find the current tag being typed (before cursor)
        const beforeCursor = value.substring(0, cursorPos);
        const lastComma = beforeCursor.lastIndexOf(',');

        return lastComma >= 0
            ? beforeCursor.substring(lastComma + 1).trim()
            : beforeCursor.trim();
    }

    search(query) {
        const url = `${this.options.apiUrl}?q=${encodeURIComponent(query)}&limit=${this.options.maxResults}`;

        fetch(url)
            .then(response => response.json())
            .then(tags => {
                this.showResults(tags);
            })
            .catch(error => {
                console.error('Tag autocomplete error:', error);
            });
    }

    showResults(tags) {
        if (tags.length === 0) {
            this.hideDropdown();
            return;
        }

        this.currentTags = tags;
        this.selectedIndex = -1;

        this.dropdown.innerHTML = '';

        tags.forEach((tag, index) => {
            const item = document.createElement('div');
            item.className = 'tag-autocomplete-item';
            item.style.cssText = `
                padding: 8px 12px;
                cursor: pointer;
                display: flex;
                align-items: center;
                gap: 8px;
            `;

            // Color indicator
            const colorBadge = document.createElement('span');
            colorBadge.style.cssText = `
                display: inline-block;
                width: 12px;
                height: 12px;
                border-radius: 50%;
                background-color: ${tag.color || '#6c757d'};
            `;

            // Tag name
            const tagName = document.createElement('span');
            tagName.textContent = tag.name;
            tagName.style.fontWeight = '500';

            // Description (if available)
            if (tag.description) {
                const desc = document.createElement('span');
                desc.textContent = ` - ${tag.description}`;
                desc.style.cssText = 'color: #6c757d; font-size: 0.85em;';
                tagName.appendChild(desc);
            }

            item.appendChild(colorBadge);
            item.appendChild(tagName);

            // Hover effect
            item.addEventListener('mouseenter', () => {
                this.selectedIndex = index;
                this.updateSelection();
            });

            item.addEventListener('click', () => {
                this.selectTag(index);
            });

            this.dropdown.appendChild(item);
        });

        this.showDropdown();
    }

    selectNext() {
        this.selectedIndex = Math.min(this.selectedIndex + 1, this.currentTags.length - 1);
        this.updateSelection();
    }

    selectPrevious() {
        this.selectedIndex = Math.max(this.selectedIndex - 1, 0);
        this.updateSelection();
    }

    updateSelection() {
        const items = this.dropdown.querySelectorAll('.tag-autocomplete-item');
        items.forEach((item, index) => {
            if (index === this.selectedIndex) {
                item.style.backgroundColor = '#e9ecef';
            } else {
                item.style.backgroundColor = 'transparent';
            }
        });

        // Scroll selected item into view
        if (this.selectedIndex >= 0 && items[this.selectedIndex]) {
            items[this.selectedIndex].scrollIntoView({
                block: 'nearest',
                behavior: 'smooth'
            });
        }
    }

    selectTag(index) {
        const tag = this.currentTags[index];
        if (!tag) return;

        // Replace current word with selected tag
        const value = this.input.value;
        const cursorPos = this.input.selectionStart;
        const beforeCursor = value.substring(0, cursorPos);
        const afterCursor = value.substring(cursorPos);
        const lastComma = beforeCursor.lastIndexOf(',');

        let newValue;
        if (lastComma >= 0) {
            // Replace last tag
            newValue = beforeCursor.substring(0, lastComma + 1) + ' ' + tag.name + ', ' + afterCursor;
        } else {
            // Replace entire value
            newValue = tag.name + ', ' + afterCursor;
        }

        this.input.value = newValue;

        // Position cursor after the inserted tag
        const newCursorPos = lastComma >= 0
            ? lastComma + tag.name.length + 3
            : tag.name.length + 2;

        this.input.setSelectionRange(newCursorPos, newCursorPos);

        this.hideDropdown();
        this.input.focus();
    }

    showDropdown() {
        // Position dropdown below input
        const rect = this.input.getBoundingClientRect();
        this.dropdown.style.top = `${this.input.offsetHeight}px`;
        this.dropdown.style.left = '0';
        this.dropdown.style.width = `${rect.width}px`;
        this.dropdown.style.display = 'block';
    }

    hideDropdown() {
        this.dropdown.style.display = 'none';
        this.selectedIndex = -1;
        this.currentTags = [];
    }
}

// Initialize autocomplete on page load
document.addEventListener('DOMContentLoaded', function() {
    const tagInputs = document.querySelectorAll('input[name="tags"]');
    tagInputs.forEach(input => {
        new TagAutocomplete(input);
    });
});
