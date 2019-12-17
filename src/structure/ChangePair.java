package structure;

import java.util.List;

import org.eclipse.jgit.diff.DiffEntry;
import org.eclipse.jgit.revwalk.RevCommit;

public class ChangePair {
	private RevCommit newCommit;
	private RevCommit oldCommit;
	private List<DiffEntry> diffs;
	
	public ChangePair(RevCommit newCommit, RevCommit oldCommit, List<DiffEntry> diffs) {
		this.newCommit = newCommit;
		this.oldCommit = oldCommit;
		this.diffs = diffs;
	}
	
	public ChangePair() {}
	
	public RevCommit getNewCommit() {
		return newCommit;
	}
	public RevCommit getOldCommit() {
		return oldCommit;
	}
	public List<DiffEntry> getDiffs() {
		return diffs;
	}
	public void setNewCommit(RevCommit newCommit) {
		this.newCommit = newCommit;
	}
	public void setOldCommit(RevCommit oldCommit) {
		this.oldCommit = oldCommit;
	}
	public void setDiffs(List<DiffEntry> diffs) {
		this.diffs = diffs;
	}
	
	

}
