'''模糊测试结果模型'''
from app.extensions import db

class FuzzResult(db.Model):
    __tablename__ = 'fuzz_results'
    fuzz_id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.Integer, db.ForeignKey('scan_tasks.task_id'), nullable=False)
    input_data = db.Column(db.Text, nullable=False)
    crash_detail = db.Column(db.Text)

    def __repr__(self):
        return f'<FuzzResult {self.fuzz_id}>'